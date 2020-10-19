/*
 * Author: Yogesh Nagarkar
 * Copyright: YesHog LLC.
 * Date: 2019 03 23
 * Module: Cloud daemon that replicates
  *        WiFi LAN functionality
 */
require('dotenv').config();
var http = require('http');
var https = require('https');
const WebSocket = require('ws');
var emitter = require('events');
var fs = require('fs');
var path = require("path");
var url = require('url');
var bodyParser = require('body-parser');
var cookieSession = require('cookie-session');
var uuid = require('uuid');
const {DefaultAzureCredential, ManagedIdentityCredential} = require('@azure/identity');
const {SecretClient} = require('@azure/keyvault-secrets');
var express = require('express');
var app = express();
var _ = require('lodash');

/* azure keyvault */
const credential = new DefaultAzureCredential();

// Replace value with your Key Vault name here
const vaultName = "yhioe-keyvault";
const azureVaultUrl = `https://${vaultName}.vault.azure.net`;

const client = new SecretClient(azureVaultUrl, credential);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.enable('trust proxy');
var sessionOptions = {
    name: 'session',
    keys: ['89987859990LKK', 'kghfnbjh=='],
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
};
app.use(cookieSession(sessionOptions));

// BEGIN FIREBASE API //
const YH_FIREBASE_REG_ENDPOINT = '/yh-registration-endpoint';
const YH_FIREBASE_DEVICE_REG_ENDPOINT = '/yh-device';
const YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY = 'user_data_endpoint_id';

var firebase = require('firebase');

var authcfg = {
    firebase: {
        config: {
            apiKey: process.env.FIREBASE_API_KEY,
            authDomain: "yeshog-17d96.firebaseapp.com",
            databaseURL: "https://yeshog-17d96.firebaseio.com",
            projectId: "yeshog-17d96",
            storageBucket: "yeshog-17d96.appspot.com",
            messagingSenderId: "1064219354329"
        },
        user: process.env.FIREBASE_USER,
        secret: process.env.FIREBASE_SECRET
    }
};

const YH_CUSTOMERS = '/yh-customers';
var firebaseApp, signedIn;

const yhioeLogMsg = (msg) => {
    var f = path.basename(__filename);
    var stack = new Error().stack

    var stackArr = stack.split('\n');
    var i, fun, lineno;
    var yhStack = [];
    for (i = 2; i < stackArr.length; i++) {
        var toks = stackArr[i].split(/\s+/);
        if (toks.length < 4) {
            continue;
        }
        fun = toks[2];
        lineno = toks[3].split(':')[1];
        if (toks[3].indexOf(f) > 0) {
            if (fun.indexOf('Object.<anonymous>') >= 0) {
                fun = f;
            }
            yhStack.push(fun + ':' + lineno);
        }
    }
    var stackLog = f + ' ' + yhStack.join(' <- ');
    stackLog = stackLog + ' ' + msg + '\n';
    console.log(stackLog);
    return stackLog.slice(0, -1);
};

const toType = (obj) => {
    /* https://stackoverflow.com/questions/7390426/
    better-way-to-get-type-of-a-javascript-variable */
    return ({}).toString.
    call(obj).
    match(/\s([a-zA-Z]+)/)[1].toLowerCase()
};

const yhGetObjectSkippingKeys = (obj, keys) => {
    var dup = {};
    for (var key in obj) {
        if (keys.indexOf(key) === -1) {
            dup[key] = obj[key];
        }
    }
    return dup;
};

const yhIsHex = (str) => {
    var regexp = /^[0-9a-fA-F]+$/;
    return regexp.test(str);
};

const yhStr2Hex = (str) => {
    var hex = '';
    if (!str || yhIsHex(str)) {
        return str;
    }
    for(var i = 0; i < str.length;i++) {
        hex += '' + str.charCodeAt(i).toString(16);
    }
    return hex;
};

const yhHex2Str = (hexstr) => {
    var charstr = '';
    if (!yhIsHex(hexstr)) {
        /* string ain't hex */
        return hexstr;
    }
    for(var i = 0; i < hexstr.length; i += 2) {
        charstr += String.fromCharCode(parseInt(hexstr.substr(i, 2), 16));
    }
    return charstr;
};

function isValidJSONString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}

function b64Decode(str) {
    var decoded = Buffer.from(str, 'base64').toString();
    var reEncodedBuf = new Buffer(decoded);
    var reEncoded = reEncodedBuf.toString('base64');
    if (reEncoded === str) {
        /* valid b64 string */
        return decoded;
    }
    return str;
}

function yhGetB64EncodedMessage(b64) {
    return JSON.parse(b64Decode(b64))
}

function yhGetTimestamp() {
    var d = new Date();
    var m = d.getMonth() + 1;
    var ms = (m < 10)? '0' + m : m.toString();
    var D = d.getDate();
    var DS = (D < 10)? '0' + D : D.toString();
    var h = d.getHours();
    var hs = (h < 10)? '0' + h : h.toString();
    var M = d.getMinutes();
    var MS = (m < 10)? '0' + M : M.toString();
    var s = d.getSeconds();
    var ss = (s < 10)? '0' + s : s.toString();

    return d.getFullYear().toString() + ms + DS
        + '-' + hs + MS + ss;
}

const yhFirebaseSignin = (email, password) => {
    if (!firebase.apps.length) {
        firebaseApp =
            firebase
                .initializeApp(authcfg.firebase.config)
                .database();
    }

    if (signedIn) {
        return Promise.resolve(true);
    }
    return firebase.auth()
        .signInWithEmailAndPassword(email, password)
        .then(() => {
            signedIn = true;
            return Promise.resolve(true);
        });
};

const yhFirebaseSignout = () => {
    yhioeLogMsg('Firebase Sign out');
    return firebase.auth().signOut();
};

const yhFirebaseCustomerSet = (customer, email) => {
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var tableRef = firebaseApp.ref( YH_CUSTOMERS +
                '/' + yhStr2Hex(email));
            tableRef.push();
            tableRef.set(customer);
            return Promise.resolve(customer);
        });
};

const yhFirebaseCustomerGet = (email) => {
    var refid = email;
    if (!yhIsHex(refid)) {
        refid = yhStr2Hex(refid);
    }
    var dataRef = null;
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            dataRef = firebaseApp.ref(YH_CUSTOMERS)
                .orderByKey()
                .equalTo(refid);
        })
        .then(() => {
            var customerVal = null;
            return dataRef.once('value', function (dataSnap) {
                dataSnap.forEach(function (childSnapshot) {
                    yhioeLogMsg('Snapshot ' +
                        JSON.stringify(childSnapshot));
                    customerVal = childSnapshot.val();
                    return Promise.resolve(customerVal);
                })
            }).then((val) => {
                yhioeLogMsg('val ' + JSON.stringify(val));
                return Promise.resolve(customerVal);
            })
        });
};

const yhFirebaseCustomerDelete = (email) => {
    var customerKey = yhIsHex(email) ? email : yhStr2Hex(email);
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var path = YH_CUSTOMERS +
                '/' + customerKey;
            var dref = firebaseApp.ref(path);
            dref.push();
            dref.set(null);
            return Promise.resolve(customerKey);
        });
};

const yhFirebaseRegistrationSet = (regdata) => {
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var path =  YH_FIREBASE_REG_ENDPOINT +
                '/' + yhStr2Hex(regdata.id);
            var tableRef = firebaseApp.ref(path);
            tableRef.push();
            tableRef.update(regdata);
            return Promise.resolve(regdata);
        });
};

function yhFirebaseCreateDeviceEndpoint(device) {
    delete device['create'];
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var path = YH_FIREBASE_DEVICE_REG_ENDPOINT +
                '/' + device.id;
            var table_ref = firebaseApp.ref(path);
            table_ref.push();
            device['ts'] = yhGetTimestamp();
            yhioeLogMsg('yhFirebaseCreateDeviceEndpoint set/create');
            return table_ref.update(device);
        }).then(() => {
            yhioeLogMsg('yhFirebaseCreateDeviceEndpoint returning ' +
                JSON.stringify((device)));
            return Promise.resolve(device)
        })
}

const yhFirebaseGetRegistrationEndpoint = (email) => {
    var id = yhStr2Hex(email);
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            return firebaseApp.ref(YH_FIREBASE_REG_ENDPOINT)
                .orderByKey()
                .equalTo(id)
                .once('value', function (data_snap) {
                    data_snap.forEach(function (childSnapshot) {
                        yhioeLogMsg('yhFirebaseGetRegistrationEndpoint ' +
                            JSON.stringify(childSnapshot.val()));
                        return childSnapshot.val();
                    })
                });
        });
};

const yhFirebaseGetDeviceEndpoint = (device) => {
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret).then(() => {
        yhioeLogMsg('unpklGetOwnerEndptFromDeviceId Getting device endpt');
        return firebaseApp.ref(YH_FIREBASE_DEVICE_REG_ENDPOINT)
            .orderByKey()
            .equalTo(device.id)
            .once('value', function (data_snap) {
                // yhioeLogMsg('unpklGetOwnerEndptFromDeviceId device: ' +
                // JSON.stringify(device) + ' data_snap.val():' + data_snap.val());
                var existing_device = data_snap.val();
                if (device.create) {
                    /* If we are asked to create or update do so */
                    var reduced = device;
                    if (existing_device) {
                        existing_device = existing_device[device.id];
                        reduced = {...existing_device, ...device};
                    }
                    return yhFirebaseCreateDeviceEndpoint(reduced)
                        .then(() => {
                            yhioeLogMsg("unpklGetOwnerEndptFromDeviceId reduced " +
                                JSON.stringify(reduced));
                            return Promise.resolve(reduced);
                        });
                } else {
                    return Promise.resolve(existing_device);
                }
            })
            .then((devicenode) => {
                var endpt = devicenode.val();
                /* by this time we must have a device */
                if (!endpt) {
                    yhioeLogMsg('yhFirebaseGetDeviceEndpoint device ' +
                        JSON.stringify(device) + ' not found/created');
                    return Promise.resolve(endpt);
                } else {
                    var dvckey = Object.keys(endpt)[0];
                    var dev = endpt[dvckey];
                    yhioeLogMsg('yhFirebaseGetDeviceEndpoint dvckey [' +
                        dvckey + ']');
                    if (Object.keys(dev)
                            .indexOf(YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY) < 0 ) {
                        yhioeLogMsg('yhFirebaseGetDeviceEndpoint ' +
                            'key ' +  YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY
                            + ' not yet set returning null');
                        return Promise.resolve(null);
                    } else {
                        var usrid = dev[YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY];
                        yhioeLogMsg('yhFirebaseGetDeviceEndpoint getting ' +
                            'registration endpoint for ' + yhHex2Str(usrid));
                        return yhFirebaseGetRegistrationEndpoint(usrid);
                    }
                }
            });
    }).catch((err) => {
        yhioeLogMsg('error ' + err.message);
        return Promise.resolve(null);
    });
};

function yhFirebaseDeleteDevice(deviceid) {
    var device_key;
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var data_ref =
                firebaseApp.ref(YH_FIREBASE_DEVICE_REG_ENDPOINT)
                    .orderByKey()
                    .startAt(deviceid)
                    .limitToFirst(1);
            return data_ref.once('value', function (data_snap) {
                yhioeLogMsg('device_rec ' +
                    JSON.stringify(data_snap.val()));
                return Promise.resolve(data_snap.val());
            })
        })
        .then((device) => {
            device_key = Object.keys(device.val())[0];
            var path = YH_FIREBASE_DEVICE_REG_ENDPOINT +
                '/' + device_key;
            yhioeLogMsg('yhFirebaseDeleteDevice deleting ' + path);
            return firebaseApp.ref(path)
                .remove()
                .then(() => {
                    return Promise.resolve(device)
                });
        });
}

const yhFirebaseGetDevice = (deviceid) => {
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret).then(() => {
        return firebaseApp.ref(YH_FIREBASE_DEVICE_REG_ENDPOINT)
            .orderByKey()
            .equalTo(deviceid)
            .once('value', function (data_snap) {
                return Promise.resolve(data_snap.val());
            });
    });
};

const yhFirebaseDeviceDeleteOwnerEndpoint = (ownerid) => {
    var removed = [];
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var data_ref =
                firebaseApp.ref(YH_FIREBASE_DEVICE_REG_ENDPOINT)
                    .orderByChild(YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY).equalTo(ownerid);
            return data_ref.once('value', function (data_snap) {
                data_snap.forEach(function(data) {
                    yhioeLogMsg('Removing reference from device ' + data.val()['id']);
                    removed.push( data.val()['id']);
                    var dref = firebaseApp.ref(YH_FIREBASE_DEVICE_REG_ENDPOINT);
                    dref.child(data.val()['id'])
                        .child(YH_FIREBASE_DEVICE_REG_ENDPOINT_KEY).remove();
                });
            })
        }).then((unused) => {
            return Promise.resolve(removed);
        })
};

const yhFirebaseSetOwnerEndpoint = (deviceid, email, owner_cloud_endpoint) => {
    var regdata = {id: yhStr2Hex(email), ...owner_cloud_endpoint, ts: yhGetTimestamp()};
    return yhFirebaseRegistrationSet(regdata);
};

const yhFirebaseDeleteOwnerEndpoint = (ownerid) => {
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret)
        .then(() => {
            var data_ref =
                firebaseApp.ref(YH_FIREBASE_REG_ENDPOINT).child(ownerid);
            return data_ref.remove();
        })
};

const yhFirebaseMonitorOwnership = (deviceid, callback) => {
    /* If device owner changed because, say we re-provisioned it
       end all sessions
     */
    var path = YH_FIREBASE_DEVICE_REG_ENDPOINT + '/' + deviceid + '/' +
        'user_data_endpoint_id';
    return yhFirebaseSignin(authcfg.firebase.user,
        authcfg.firebase.secret).then(() => {
        return firebaseApp.ref(path)
            .on('value', function(snapshot) {
                return callback(deviceid, snapshot.val())
        });
    });
};

// END FIREBASE API //

/* global variables */
var yhioeDefaultOpts = {
    ca: null,
    cert: null,
    key: null
};
var yhioeModuleData = {
    yhioeHttpServer: null,
    yhioeDeviceWebSockets: [],
    yhioeOwnerSessions: [],
    yhioeLogFilter: [],
    yhioeDeviceMsgCount: 0, /* global ctr for xids */
};
/* end global variables */

/* constants */
const yhRetainMaxRecordsPerDevice = 36;
/* end constants */

const yhioeReturnResponse = (res, code, obj) => {
    if (!res.headersSent) {
        res.writeHead(code, { 'Content-Type': 'application/json' });
    }
    if (obj) {
        return res.end(JSON.stringify(obj));
    }
    return res.end();
};

const yhioeReturnResponseJson = (res, code, jsonstr) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    return res.end(jsonstr);
};

const yhioeGetRequestPath = (req) => {
    var pathname = url.parse(req.url).pathname;
    return pathname.toLowerCase();
};

const YHIOE_OWNER_NOT_AUTHENTICATED = 0;
const YHIOE_OWNER_AUTHREQUESTED     = 1;
const YHIOE_OWNER_AUTHSUCCESS       = 2;
const YHIOE_SESSION_STATUS_OK       = 1;
const YHIOE_SESSION_STATUS_DORMANT  = 2;
const YHIOE_SESSION_STATUS_FAIL     = -1;
const YHIOE_OWNER_AUTHFAIL          = -2;
const YHIOE_SESSION_STATUS_CONT     = 0;
const YHIOE_SESSION_CREATE          = 1;
const YHIOE_SESSION_UPDATE          = 2;

const yhioeCreateNewdevice = (id) => {
    return {
        device: {
            id: id,
            wss: new WebSocket.Server({ noServer: true }),
            ws: null,
            owner: null,
            pingTimer: null,
            online: false,
            yhDhcpAssignedIps: [],
            yhConntrack: [],
            yhInetAccessCloudInfo: []
        }
    };
};

const yhioeHandleOwnershipChange = (deviceid, newowner) => {
    var promiseArray = [];
    for (var i = 0;
         i < yhioeModuleData.yhioeDeviceWebSockets.length; i++) {
        var device = yhioeModuleData.yhioeDeviceWebSockets[i];
        if (device.id === deviceid) {
            device.owner = newowner;
            for (var j = 0;
                 j < yhioeModuleData.yhioeOwnerSessions.length;
                 j++) {
                promiseArray.push(
                    yhioeModuleData.yhioeOwnerSessions[j].res.end('{}'));
            }
        }
    }
    return Promise.all(promiseArray);
};

const yhioeGetMsgStatus = (msg) => {
    /* handle search and command results here */
    var retcode = 101; /* continue */
    yhioeLogMsg(JSON.stringify(msg));
    switch (msg.endpt) {
        case '/a':
        case '/c':
            retcode = msg.status;
            break;
        default:
            break;
    }
    return retcode;
};

const yhioeRouteSessionAuth = (session, device, msg) => {
    var deviceEntry = _.find(session.deviceList,
        {id: device.id});
    if (!deviceEntry) {
        yhioeLogMsg('device ' + device.id + ' not found');
        return null;
    }
    if (msg.device !== deviceEntry.id) {
        yhioeLogMsg('auth for device ' +
            msg.device + ' !== ' + device.id);
        return null;
    }
    var currentAuthState = deviceEntry.authState;

    yhioeLogMsg(JSON.stringify(deviceEntry));
    var ret = 404;
    switch (currentAuthState) {
        case YHIOE_OWNER_AUTHREQUESTED:
        case YHIOE_OWNER_NOT_AUTHENTICATED:
            ret = yhioeGetMsgStatus(msg);
            if (ret === 200) {
                deviceEntry.authState = YHIOE_OWNER_AUTHSUCCESS;
                /* Also save the 'cookie' so we can send
                   it back as auth_token
                 */
                deviceEntry.authToken = msg['message'];
                yhioeLogMsg('setting device: ' + deviceEntry.id +
                    ' authToken ' + deviceEntry.authToken);
            }
            if (ret >= 400) {
                deviceEntry.authState = YHIOE_OWNER_AUTHFAIL;
            }
            break;
        case YHIOE_OWNER_AUTHSUCCESS:
            break;
        case YHIOE_OWNER_AUTHFAIL:
            break;
    }
    return msg;
};

const yhioePrintSessions = (nolog, filterBySessionId) => {
    var sessArr = [];
    for (var i = 0; i < yhioeModuleData.yhioeOwnerSessions.length; i++) {
        var sess = yhioeModuleData.yhioeOwnerSessions[i];
        if (filterBySessionId) {
            if (sess.sessionid != filterBySessionId) {
                continue;
            }
        }
        var sessStr = 'session [' + i + '] id: ' +
            sess.sessionid + ' owner: ' + yhHex2Str(sess.owner) +
            ' deviceList: ' + JSON.stringify(sess.deviceList) +
            ' deviceMessageQueue: ' +
            JSON.stringify(sess.deviceMessageQueue);
        sessArr.push(sessStr);
    }
    if (nolog) {
        return sessArr.join(',');
    }
    yhioeLogMsg(sessArr.join(','));
    return sessArr.join(',');
};

const yhioeGetEventName = (id, deviceId, endpt, sepr) => {
    var sep = sepr? sepr : ':';
    return id + sep + deviceId + sep + endpt;
};

const yhioeEmitSessionEvent = (session, eventName, messages) => {

    /* Before emitting a session event make sure
     * that we have pending messages in the queue
     */
    var endpt = eventName.split(':')[2];
    var device = eventName.split(':')[1];
    yhioeLogMsg('deviceMessageQueue ' +
        JSON.stringify(
            yhioeRemovePasswd(session.deviceMessageQueue)) +
        ' result endpt ' + endpt);

    if (endpt === '/n/g') {
        yhioeLogMsg('emitting event for ' +
            endpt + ' ' + eventName + ' messages ' +
            JSON.stringify(messages));
        session.eventEmitter.emit(eventName, messages);
    } else {
        var queuedMsg = _.find(session.deviceMessageQueue,
            {
                device: device,
                endpt: endpt
            });
        if (queuedMsg) {

            yhioeLogMsg('emitting event ' +
                ' for ' + endpt + ' ' + eventName +
                ' messages ' + JSON.stringify(messages));

            session.eventEmitter.emit(eventName, messages);
        } else {
            yhioeLogMsg('discarding event ' +
                + endpt + ' ' + eventName + ' messages ' +
                JSON.stringify(yhioeRemovePasswd(messages)));
        }
    }
};

const yhioeSyncDeviceDataToConnectedOwner = (session, device, msgs) => {
    var systemMessages = [];
    var deviceMessages = [];
    for (var i = 0; i < msgs.length; i++) {
        var deviceEntry = _.find(session.deviceList,
            {id: device.id});
        var msg = msgs[i];
        switch (msg['table']) {
            case 'system':
                switch (msg['endpt']) {
                    case '/a':
                        if (msg.device === deviceEntry.id) {
                            yhioeLogMsg('system message device ' +
                                JSON.stringify(deviceEntry) +
                                ' message ' + JSON.stringify(msg));
                            if (deviceEntry.authState !== YHIOE_OWNER_AUTHSUCCESS) {
                                if (yhioeRouteSessionAuth(session, device, msg)) {
                                    systemMessages.push(msg);
                                }
                            }
                        } else {
                            yhioeLogMsg('skipping auth device ' +
                                device.id + ' msg.device ' + msg.device);
                        }
                        break;
                    default:
                        systemMessages.push(msg);
                        break;
                }
                break;
            case 'yh_inet_access_cloud_info':
            case 'yh_dhcp_assigned_ips':
            case 'yh_conntrack':
                /* Traffic and other live messages */
                if (deviceEntry.authState === YHIOE_OWNER_AUTHSUCCESS) {
                    msg['endpt'] = '/n/g';
                    deviceMessages.push(msg);
                }
                break;
            default:
                break;
        }
    }
    return {
        deviceMessages: [...deviceMessages],
        systemMessages: [...systemMessages]
    };
};

const yhioeProcessWSRunCblist = (session, device, msgs) => {
    for (var i = 0; i < session.cblist.length; i++) {
        var isCached = 'live';
        if (msgs) {
            /* We are called from ws.on('message') */
            session.messagesFromDevices = [...session.messagesFromDevices,
                ...msgs];
        } else {
            /* We are called on a new session */
            session.messagesFromDevices = [
                ...session.messagesFromDevices,
                ...device.yhInetAccessCloudInfo,
                ...device.yhDhcpAssignedIps
            ];
        }
        yhioeLogMsg(session.sessionid +
            ' sending messagesFromDevices.length ' +
            session.messagesFromDevices.length + ' ' + isCached + ' ' +
            ' messages ' + device.id +
            ' to owner ' + yhHex2Str(device.owner));
        var cbresult = session.cblist[i](session, device,
            session.messagesFromDevices);
        if (cbresult.systemMessages.length > 0) {
            for (var j = 0; j < cbresult.systemMessages.length; j++) {
                var eventName = yhioeGetEventName(session.sessionid,
                    device.id, cbresult.systemMessages[j].endpt);
                yhioeEmitSessionEvent(session, eventName, cbresult);
            }
        }
        if (cbresult.deviceMessages.length > 0) {
            var eventName = yhioeGetEventName(session.sessionid,
                device.id, '/n/g');
            yhioeEmitSessionEvent(session, eventName, cbresult);
        }
    }
};

const yhioeWSMessageCheckSessions = (device) => {
    /*
     * A device's status may be asked by multiple owners at the
     * same time
     */
    var subscribers = [];

    yhioeLogMsg('yhioeWSMessageCheckSessions: sessions count ' +
        yhioeModuleData.yhioeOwnerSessions.length);

    for (var i = 0; i < yhioeModuleData.yhioeOwnerSessions.length; i++) {
        var sess = yhioeModuleData.yhioeOwnerSessions[i];

        yhioeLogMsg('yhioeWSMessageCheckSessions: looking for ' +
            device.id + ' in sess ' + sess.sessionid + ' deviceList ' +
            JSON.stringify(sess.deviceList));

        if (sess.owner !== device.owner) {
            continue;
        }
        for (var j = 0; j < sess.deviceList.length; j++) {
            if (sess.deviceList[j].id === device.id) {
                subscribers.push(sess);
            }
        }
    }
    /* we have a session interested in messages */
    yhioeLogMsg('yhioeWSMessageCheckSessions: device message' +
        ' subscribers ' +
        JSON.stringify(_.map(subscribers, 'sessionid')));

    return subscribers;
};

const yhioeGetSessionToDeviceAuthState = (session, device, asString) => {
    var dl = _.find(session.deviceList, {id: device.id});
    var ret = -1;
    var retStr = '';
    if (dl) {
        ret = dl.authState;
    }
    if (asString) {
        switch (ret) {
            case YHIOE_OWNER_NOT_AUTHENTICATED:
                retStr = 'YHIOE_OWNER_NOT_AUTHENTICATED';
                break;
            case YHIOE_OWNER_AUTHREQUESTED:
                retStr = 'YHIOE_OWNER_AUTHREQUESTED';
                break;
            case YHIOE_OWNER_AUTHSUCCESS:
                retStr = 'YHIOE_OWNER_AUTHSUCCESS';
                break;
            case YHIOE_OWNER_AUTHFAIL:
                retStr = 'YHIOE_OWNER_AUTHFAIL';
                break;
            default:
                retStr = 'YHIOE_OWNER_AUTH_ERROR';
                break;
        }
    }
    return asString? retStr: ret;
};

const yhioeRefreshDeviceDataWindow = (device, msgs) => {
    /* We always promise to serve fresh hot air upon your return */
    //device.cachedMessageList = [...device.cachedMessageList, ...msgs];
    for (var ct = 0; ct < msgs.length; ct++) {
        switch (msgs[ct].table) {
            case 'yh_inet_access_cloud_info':
                device.yhInetAccessCloudInfo.push(msgs[ct]);
                if (device.yhInetAccessCloudInfo.length >
                    yhRetainMaxRecordsPerDevice) {
                    var truncateCt =
                        device.yhInetAccessCloudInfo.length -
                        yhRetainMaxRecordsPerDevice;
                    device.yhInetAccessCloudInfo.splice(0,
                        truncateCt);
                    yhioeLogMsg('yhioeProcessWSMessage: truncating '
                        + truncateCt +
                        ' yhInetAccessCloudInfo records');
                }
                yhioeLogMsg('yhioeProcessWSMessage: cached ' +
                    device.yhInetAccessCloudInfo.length +
                    ' yhInetAccessCloudInfo records');
                break;
            case 'yh_conntrack':
                device.yhConntrack.push(msgs[ct]);
                if (device.yhConntrack.length >
                    yhRetainMaxRecordsPerDevice) {
                    var truncateCt =
                        device.yhConntrack.length -
                        yhRetainMaxRecordsPerDevice;
                    device.yhConntrack.splice(0,
                        truncateCt);
                    yhioeLogMsg('yhioeProcessWSMessage: truncating '
                        + truncateCt +
                        ' yhConntrack records');
                }
                yhioeLogMsg('yhioeProcessWSMessage: cached ' +
                    device.yhInetAccessCloudInfo.length +
                    ' yhInetAccessCloudInfo records');
                break;
            case 'yh_dhcp_assigned_ips':
                var connected_device = _.find(device.yhDhcpAssignedIps,
                    {srcid: msgs[ct].srcid});
                if (!connected_device) {
                    device.yhDhcpAssignedIps.push(msgs[ct]);
                }
                yhioeLogMsg("synced yh_dhcp_assigned_ips: " +
                    JSON.stringify(device.yhDhcpAssignedIps));
                break;
        }
    }
};

const yhioeProcessWSMessage = (device, msg) => {
    /* Incoming WebSocket Msg callback. Meaning
     * device sent some data to cloud */
    yhioeLogMsg(' processing message from device ' +
        device.id + ' message ' + msg);
    var msgObj = JSON.parse(msg);
    for (var i = 0; i < msgObj.length; i++) {
        msgObj[i].device = device.id;
    }
    /* But whether there are subscribers or not, always
     * refresh the window
     */
    yhioeRefreshDeviceDataWindow(device, msgObj);
    /* Are any owner(s) connected? to view data */
    var subscriberSessions = yhioeWSMessageCheckSessions(device);
    /* Yes owners want to view live data */
    for (var i = 0; i < subscriberSessions.length; i++) {
        /* And then also sync the new message that the device just
        *  sent .. if any */
        yhioeProcessWSRunCblist(
            subscriberSessions[i], device, msgObj);
    }

};

const yhioeSendCloudPing = (device) => {
    device.ws.send(JSON.stringify({
        endpt: "/cloudPing",
        ts: yhGetTimestamp()
    }))
};

const yhioeOnDeviceDisconnect = (device) => {
    device.online = false;
    yhioeDeviceDel(device.id);
    clearInterval(device.pingTimer);
    var sessions = _.filter(yhioeModuleData.yhioeOwnerSessions,
        function f(sess) { return sess.owner === device.owner});
    if (!sessions) {
        return;
    }
    var killSessions = [];
    for (var i = 0; i < sessions.length; i++) {
        _.remove(sessions[i].deviceList, function(dvc) {
            return dvc.id === device.id;
        });
        if (sessions[i].deviceList.length === 0) {
            killSessions.push(sessions[i]);
        }
    }
    for (var j = 0; j < killSessions.length; j++) {
        _.remove(yhioeModuleData.yhioeOwnerSessions,
            function(sess) {
            return sess.sessionid === killSessions[j].sessionid
        });
    }
    yhioePrintSessions();
};

const yhioeHttpHandleUpgradeWs = (req, socket, head, deviceid) => {
    var device = null;
    for (var i = 0; i < yhioeModuleData.yhioeDeviceWebSockets.length; i++) {
        if (yhioeModuleData.yhioeDeviceWebSockets[i].id === deviceid) {
            /* we know this device. it was possibly down */
            device = yhioeModuleData.yhioeDeviceWebSockets[i];
            yhioeLogMsg('yhioeHttpHandleUpgrade: device likely down ' +
                'cleaning up stale connection for ' + deviceid +
                ' owner ' + device.owner);

            device.ws.close();
            break;
        }
    }
    /* Create a new websocket server */
    device = yhioeCreateNewdevice(deviceid).device;

    /* set callbacks and fire them */
    device.wss.on('connection', (ws) => {
        device.ws = ws;
        /*
         * setup a timer here which sends back keep alive
         * data back to the device.
         */
        device.pingTimer =
            setInterval(yhioeSendCloudPing, 28000, device);
        device.online = true;
        ws.on('message', (msg) => {
            yhioeLogMsg('yhioeHttpHandleUpgradeWs ws.on message: '
                + device.id);
            if (device.online === false) {
                yhioeLogMsg('yhioeHttpHandleUpgradeWs ws.on message: '
                    + device.id + ' was offline marking online');
                device.online = true;
            }
            return yhioeProcessWSMessage(device, msg);
        });
        ws.on('close', (_unused) => {
            yhioeLogMsg('yhioeHttpHandleUpgradeWs: websocket closed by ' +
            device.id);
            yhioeOnDeviceDisconnect(device);
        });
    });
    device.wss.handleUpgrade(req, socket, head, function done(ws) {
        yhioeLogMsg('yhioeHttpHandleUpgradeWs ' +
            'device.wss.handleUpgrade: ' + device.id);
        device.wss.emit('connection', ws, req);
    });
    yhioeModuleData.yhioeDeviceWebSockets.push(device);
    return Promise.resolve(device);
};

const yhioeHttpHandleUpgrade = (req, socket, head) => {
    var path = yhioeGetRequestPath(req);
    var deviceid = path.split('/').slice(-1)[0];

    if (!(yhIsHex(deviceid) &&
            path.split('/').slice(-2)[0] === 'device')) {
        yhioeLogMsg('error is hex ' +
            yhIsHex(deviceid) + ' deviceid ' + deviceid);
        socket.end('HTTP/1.1 404  ' + path + '\r\n');
        socket.destroy();
        return null;
    }

    return yhioeHttpHandleUpgradeWs(req, socket, head, deviceid)
        .then((unused) => {
            yhioeLogMsg("fetching device endpoint for " + deviceid);
            return yhFirebaseGetDeviceEndpoint({id: deviceid})
                .then((owner_rec) => {
                    var owner = Object.keys(owner_rec)[0];
                    yhioeLogMsg("device: " + deviceid + " owner: " + owner);
                    return yhioeHandleOwnershipChange(deviceid, owner);
                    /* TODO: add catch here if firbase connectivity is hosed */
        })
    }).then((unused_ownership_promises) => {
        return yhFirebaseMonitorOwnership(deviceid,
            yhioeHandleOwnershipChange);
    });
};

const yhioeCheckOnlineDevices = (session, deviceFilter, cb, cbarg) => {
    var owner = session.owner;
    var res = 0;
    yhioeLogMsg('yhioeCheckOnlineDevices: owner ' + owner +
        ' deviceFilter ' + JSON.stringify(deviceFilter));
    var devicelist = [];
    for (var i = 0; i < yhioeModuleData.yhioeDeviceWebSockets.length; i++) {
        var device = yhioeModuleData.yhioeDeviceWebSockets[i];
        if (device.owner === owner ) {
            yhioeLogMsg('yhioeCheckOnlineDevices: device ' +
                device.id + ' is online owner ' + yhHex2Str(owner));
            if (deviceFilter) {
                for (var j = 0; j < deviceFilter.length; j++) {
                    if (deviceFilter[j].id === device.id) {
                        yhioeLogMsg('yhioeCheckOnlineDevices: including ' +
                            'deviceFilter online device ' + device.id);
                        devicelist.push(device);
                        if (cb) {
                            if ((res = cb(session, device, cbarg)) < 0) {
                                /* Something bad happened in
                                 * the callback
                                 */
                                yhioeLogMsg('yhioeCheckOnlineDevices:' +
                                    ' callback failed result ' + res);
                            }
                        }
                    } else {
                        yhioeLogMsg('yhioeCheckOnlineDevices: ' +
                            'skipping ' + device.id);
                    }
                }
            } else {
                devicelist.push(device);
                device.online = true;
                if (cb) {
                    if ((res = cb(session, device, cbarg)) < 0) {
                        /* Something bad happened in
                         * the callback
                         */
                        yhioeLogMsg('yhioeCheckOnlineDevices:' +
                            ' !deviceFilter ' + ' callback failed ' +
                            'result ' + res);
                        devicelist.push(device);
                    }
                }
            }
        } else {
            yhioeLogMsg('yhioeCheckOnlineDevices: device ' +
                yhHex2Str(device.owner) + ' !== ' + yhHex2Str(owner));
        }
    }
    return devicelist;
};

const yhioeGetOnlineDevicesForOwner = (req, session, cb, cbarg) => {
    var deviceFilterStr = req.body.devices;
    var deviceFilter = null;
    if (deviceFilterStr) {
        if (isValidJSONString(deviceFilterStr)) {
            deviceFilter = JSON.parse(deviceFilterStr);
        }
    }
    return yhioeCheckOnlineDevices(session,
        deviceFilter, cb, cbarg);
};

const yhioeDeviceGet = (id) => {
    return _.find(yhioeModuleData.yhioeDeviceWebSockets, {id: id});
};

const yhioeDeviceDel = (id) => {
    _.remove(yhioeModuleData.yhioeDeviceWebSockets,
        function (device) {
        return device.id === id
    });
};

const yhioeGenerateDeviceMessageXid = () => {
    var xid = yhGetTimestamp() + '-' +
        ('000' + yhioeModuleData.yhioeDeviceMsgCount).slice(-4);
    yhioeModuleData.yhioeDeviceMsgCount += 1;
    return xid;
};

const yhioeGetMessage = (origMessage, extraAttrs) => {
    /* If device wants other attributes add them here */
    var otherAttrs = {xid: yhioeGenerateDeviceMessageXid()};
    if (extraAttrs) {
        otherAttrs = {...otherAttrs, ...extraAttrs};
    }
    return JSON.stringify({...origMessage, ...otherAttrs});
};

const yhioeEnqueueDeviceMessage = (session, device, messageToDevice) => {
    /* You may not hammer a device endpoint when
     * one is already queued up
     */

    var existingTxMsg =
        _.find(session.deviceMessageQueue,
            {
                device: device.id,
                endpt: messageToDevice.endpt
            });
    var eventName = yhioeGetEventName(session.sessionid,
        device.id, messageToDevice.endpt);
    if (existingTxMsg) {
        yhioeLogMsg(' endpt ' +
            messageToDevice.endpt + ' is already queued xid: ' +
            messageToDevice.xid);
        return existingTxMsg;
    } else {
        if (device.online) {
            /* dont attempt to stringify req/res and shoot ourselves
               in the face
             */
            device.ws.send(JSON.stringify(messageToDevice));
            /* but do queue up the real message with req/res
             */
            session.deviceMessageQueue.push(messageToDevice);
            /*
             * If after 40 seconds we do not receive a message
             * generate a message from the device we send a timeout
             * event
             */
            var timeoutMessage = {
                ...messageToDevice,
                status: 404,
                message: 'timeout',
                trace: []
            };
            setTimeout(yhioeEmitSessionEvent, 40000,
                session, eventName,
                {
                    systemMessages: [timeoutMessage],
                    deviceMessages: []
                });
            session.eventQueue.push(eventName);
            yhioeLogMsg('enqueue ' + eventName +
                        ' ' + device.id + ' endpt ' +
                        messageToDevice.endpt + ' ' +
                                      JSON.stringify(
                                  yhioeRemovePasswd(
                                  messageToDevice)));
        } else {
            yhioeLogMsg(device.id + ' is not online skipping ' +
                ' endpt ' + messageToDevice.endpt + ' ' +
                JSON.stringify(messageToDevice));
        }
    }
    return messageToDevice;
};

const yhioeDequeueDeviceMessage = (session, eventName) => {

    yhioeLogMsg(eventName +
        ' deviceMessageQueue ' +
        JSON.stringify(yhioeRemovePasswd(
            session.deviceMessageQueue)));
    var device = eventName.split(':')[1];
    var endpt = eventName.split(':')[2];

    var dmq = _.find(session.deviceMessageQueue,
        {
            device: device,
            endpt: endpt
        });

    if (!dmq) {
        yhioeLogMsg('!dmq ' + dmq + ' FAILED ' +
            eventName + ' discarding event ' + eventName +
        ' eventQueue ' + JSON.stringify(session.eventQueue));
        return null;
    }

    /* Now that we have a response, yank it from the Queue */
    _.remove(session.deviceMessageQueue,
        function (v) {
        return v.device === device &&
            v.endpt === endpt });
    _.remove(session.eventQueue,
        function(e) { return e === eventName });

    yhioeLogMsg('dmq OK device ' +
        JSON.stringify(session.deviceMessageQueue));
    return eventName;
};


const yhioeWSCleanupCb = (session, cbresult) => {
    yhioeLogMsg('removing session ' +
                 session.id);
    session.messagesFromDevices = [];
    _.remove(yhioeModuleData.yhioeOwnerSessions,
        {sessionid: session.id});
    yhioePrintSessions();
};

const yhioeOwnerNewAppSession = (props) => {
    var dfltSession = {
        sessionid: null,
        status: YHIOE_SESSION_STATUS_FAIL,
        owner: null,
        eventEmitter: new emitter.EventEmitter(),
        eventQueue: [],
        deviceList: [],
        cblist: [yhioeSyncDeviceDataToConnectedOwner],
        cleanupCb: yhioeWSCleanupCb,
        deviceMessageQueue: [],
    };
    var sess = {...dfltSession, ...props};
    yhioeLogMsg('yhioeOwnerNewAppSession: ' +
                sess.sessionid + ' deviceList: ' +
               JSON.stringify(sess.deviceList));
    yhioeModuleData.yhioeOwnerSessions.push(sess);
    return sess;
};

const yhioeSetOnClose = (req, res) => {
    req.on('close', function() {
        yhioeLogMsg('close sess ' +
            JSON.stringify(req.session));
        res.end();
        yhioeWSCleanupCb(req.session, null);
    });
    req.on('abort', function() {
        yhioeLogMsg('abort sess ' +
            JSON.stringify(req.session));
        res.end();
        yhioeWSCleanupCb(req.session, null);
    });
    req.on('error', function() {
        yhioeLogMsg('error sess ' +
            JSON.stringify(req.session));
        res.end();
        yhioeWSCleanupCb(req.session, null);
    });
    yhioeLogMsg('setting on close/abort/error handlers');
}

const yhioeCheckDeviceSession = (req, res, endpt, status, create) => {
    var errors = [];
    /* Return an existing if it exists or create a new one */
    yhioeLogMsg('req.session.owner: ' + req.session.owner);
    yhioeSetOnClose(req, res);
    yhioePrintSessions();
    var sessionDeviceList = yhioeGetOnlineDevicesForOwner(req,
        req.session, null, null);
    if (!sessionDeviceList.length) {
        errors.push(yhioeLogMsg('No devices found online' +
            ' for req.session.owner: ' +
            req.session.owner));
        return {status: 500, errors: errors, session: null};
    }

    /* Now we have devices online check to see if there is a session */

    var sess =_.find(yhioeModuleData.yhioeOwnerSessions,
                        {sessionid: req.session.id});
    if (!sess) {
        if (create === YHIOE_SESSION_CREATE) {
            sess = yhioeOwnerNewAppSession({
                sessionid: req.session.id,
                owner: req.session.owner,
                status: YHIOE_SESSION_STATUS_FAIL,
                messagesFromDevices: [],
                deviceList:
                    _.transform(sessionDeviceList,
                        function(destArray, srcObject, idx) {
                            destArray.push({
                                id: srcObject.id,
                                authState: YHIOE_OWNER_NOT_AUTHENTICATED,
                                authToken: null
                            })
                        })
            });
        } else {
            errors.push(yhioeLogMsg('session: ' +
            req.session.id + ' not found' +
                yhioePrintSessions(1)));
            return {status: 500, errors: errors, session: null};
        }
    } else {
        /* found session */
        if (create === YHIOE_SESSION_UPDATE) {
            yhioeLogMsg('YHIOE_SESSION_UPDATE ' +
                yhioePrintSessions(1, sess.sessionid));
            return {status: 200, errors: errors, session: sess};
        } else {
            errors.push(yhioeLogMsg('session ' + req.session.id +
                ' op ' + create + 'not defined'));
            return {status: 500, errors: errors, session: null};
        }
    }
    /* new session created */
    return {status: 200, errors: errors, session: sess};
};

const yhioeSendMessageToDevices = (req, res, session, message, devices) => {
    yhioeLogMsg('yhioeSendMessageToDevices: ' +
        JSON.stringify(devices));
    for (var i = 0; i < devices.length; i++) {
        var device = yhioeDeviceGet(devices[i].id);
        /* we only want to send to one device */
        if (message.hasOwnProperty('targetYhioeDevice') &&
            message.targetYhioeDevice) {
            if (message.targetYhioeDevice !== device.id) {
                yhioeLogMsg('skipping device ' + device.id +
                ' targetYhioeDevice is ' + message.targetYhioeDevice);
                continue;
            }
        }
        var sessDeviceEntry =
            _.find(session.deviceList,{id: device.id});
        var authToken = sessDeviceEntry.authToken;
        var msg = yhioeGetMessage(message,
            {
                device: device.id,
                auth_token: authToken
            });
        if (!(device && message)) {
            return null;
        }
        var mesg = JSON.parse(msg);
        yhioeEnqueueDeviceMessage(session, device, mesg);
    }
    yhioeLogMsg(' queued events ' +
        JSON.stringify(session.eventQueue));
};

const yhioeSyncLive = (session) => {
    /* TODO: we may want to deviceFilter here */
    yhioeLogMsg('yhioeSyncLive syncing session ' +
        session.sessionid);
    var devices = yhioeCheckOnlineDevices(session,
        null, yhioeProcessWSRunCblist, null);
    yhioeLogMsg('yhioeSyncLive devices');
};

const yhioeCheckSession = (req, res, endpt) => {

    if (!(req.session && req.session.id)) {
        var errors = [
            yhioeLogMsg('req.session ' +
            req.session? 'ok':'not found ' +
                ' session ' + ' no valid session found')];

        yhioeReturnResponse(res, 404,
            {error: 'req.session ' +
                req.session? 'ok':'not found ' +
                    'req.session.id ' + req.session.id +
                    'no valid session found'});

        return {status: 404, errors: errors, session: null};
    }

    yhioeLogMsg( 'checking session for ' + ' endpt ' +
        endpt + ' ' + JSON.stringify(req.session));

    /* If a session was found we had marked its status
       as dormant. If it was found then we set it back to OK
       and start live streaming
     */
    var sessCheck = yhioeCheckDeviceSession(req, res,
        endpt, YHIOE_SESSION_STATUS_OK,
        YHIOE_SESSION_UPDATE);
    var sess = sessCheck.session;
    if (!sess) {
        yhioeLogMsg('user not authenticated ' +
            'redirecting');
    }
    return sessCheck;
};

const yhioeReturnDeviceResponses = (req, res, eventName, systemMessages) => {
    var bodyMessages = [];
    var endpt = eventName.split(':')[2];
    var msg, msgObj;
    var success = 1;
    for (var i = 0; i < systemMessages.length; i++) {
        var smsg = systemMessages[i];
        if (endpt !== smsg.endpt) {
            continue;
        }
        if (smsg.status === 200) {
            switch (smsg.endpt) {
                case '/a':
                    bodyMessages.push({
                        status: 'ok',
                        device: smsg.device
                    });
                    break;
                case '/n/g':
                    bodyMessages.push(smsg);
                    break;
                default:
                    msg = b64Decode(smsg['message']);
                    msgObj = JSON.parse(msg);
                    var typ = toType(msgObj);
                    switch (typ) {
                        case 'array':
                            bodyMessages = [...bodyMessages, ...msgObj];
                            break;
                        case 'object':
                            bodyMessages = [...bodyMessages, msgObj];
                            break;
                        default:
                            yhioeLogMsg('cannot handle type ' +
                                typ);
                    }
                    break;
            }
        } else {
            yhioeLogMsg('failed on ' +
                smsg.device + ' msg ' +
            JSON.stringify(smsg));
            success = 0;
            break;
        }
    }
    if (success) {
        yhioeReturnResponse(res,
            200,
            bodyMessages.length? bodyMessages: null);
    } else {
        yhioeReturnResponse(res, 404);
    }
};

const yhioeRemovePasswd = (msg) => {
    var typ = toType(msg);
    var msgCopy = null;
    switch (typ) {
        case 'array':
            msgCopy = [];
            for (var i = 0; i< msg.length; i++) {
                var clon = {...msg[i]};
                if (clon.hasOwnProperty("password")) {
                    delete clon["password"];
                }
                msgCopy.push(clon);
            }
            break;
        case 'object':
            msgCopy = {...msg};
            delete msgCopy["password"];
            break;
        default:
            break;
    }
    return msgCopy;
}

const yhioeSendCmdToDevices = (req, res, fields, overrideEndpt) => {
    var endpt = overrideEndpt? overrideEndpt: req.originalUrl;
    var targetYhioeDevice = null;
    if (req.params.device) {
        /* this request is for a specific device */
        var endptTokens = endpt.split('/');
        endptTokens.pop();
        targetYhioeDevice = req.params.device;
        yhioeLogMsg('targetYhioeDevice: ' + targetYhioeDevice);
        endpt = endptTokens.join('/');
    }
    var bodyparams = {targetYhioeDevice: targetYhioeDevice};
    if (fields) {
        bodyparams = {
            ...fields, ...bodyparams
        };
    }
    var msg = {endpt: endpt, ...bodyparams};
    yhioeLogMsg('msgToSend: ' +
        JSON.stringify(yhioeRemovePasswd(msg)));
    var sess, sessCheck;
    if (endpt === '/a') {
        sessCheck = yhioeCheckDeviceSession(req, res,
            endpt, YHIOE_SESSION_STATUS_FAIL,
            YHIOE_SESSION_CREATE);
        sess = sessCheck.session;
    } else {
        sessCheck = yhioeCheckSession(req, res, endpt);
        sess = sessCheck.session;
    }
    if (sess) {
        yhioeSendMessageToDevices(req, res, sess,
            msg, sess.deviceList);
        for (var i = 0; i < sess.deviceList.length; i++) {
            var eventName = yhioeGetEventName(sess.sessionid,
                sess.deviceList[i].id, endpt);
            sess.eventEmitter.once(eventName, (messages) => {
                var st = yhioeDequeueDeviceMessage(sess, eventName);
                yhioeReturnDeviceResponses(req, res,
                    eventName, messages.systemMessages);
            });
        }
    } else {
        yhioeLogMsg('yhioeSendCmdToDevices: ' + endpt +
            ' failed session not found');
        yhioeReturnResponse(res, sessCheck.status, sessCheck.errors);
    }
    /* if the user is not able to authenticate to a single owned device
    *  log out */
    return sess;
};

/* web facing endpoints */
app.get('/', (req, res) => {
    yhioeLogMsg("app.get(\'/\')");
    req.session.client = req.headers['x-forwarded-for']
        || req.connection.remoteAddress;
    req.session.id = uuid();
    yhioeLogMsg("req.session.client = " + req.session.client);
    return yhioeReturnResponse(res, 200,
        {status: 'ok'});
});

app.post('/', (req, res) => {
    yhioeLogMsg('app.post("/") session ' + JSON.stringify(req.session));
    yhioeLogMsg('app.post("/") user ' + req.body.user);
    yhioeLogMsg('app.post("/") User-Agent: ' + req.headers['user-agent']);
    if (!req.body.email) {
        yhioeLogMsg('app.post("/")  bad request email missing');
        return yhioeReturnResponse(res, 404,
            {error: 'bad request email missing'});
    }
    if (!req.body.user) {
        yhioeLogMsg('app.post("/")  bad request user missing');
        return yhioeReturnResponse(res, 404,
            {error: 'bad request username missing'});
    }
    if (!req.body.password) {
        yhioeLogMsg('app.post("/") bad request pass missing');
        return yhioeReturnResponse(res, 404,
            {error: 'valid credentials needed for access'});
    }
    /* TODO: handle auth */

    /* we get a session after login to any device is successful
     * once
     */
    yhioeLogMsg('app.post("/") request ok');
    req.session.owner = yhStr2Hex(req.body.email);
    var creds = {
        user: req.body.user,
        password: req.body.password,
        owner: req.session.owner
    };
    return yhioeSendCmdToDevices(req, res, creds, '/a');
});

app.get('/u/:id/:device?', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

app.get('/policy/ban/:id/:device?', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

app.get('/n/g', (req, res) => {
    var sessCheck = yhioeCheckSession(req, res, '/n/g');
    var sess = sessCheck.session;
    if (sess) {
        yhioeSyncLive(sess); /* and this potentially never ends */
        for (var i = 0; i < sess.deviceList.length; i++) {
            var eventName = yhioeGetEventName(sess.sessionid,
                sess.deviceList[i].id, '/n/g');
            sess.eventEmitter.on(eventName, (messages) => {
                var msgs = messages.deviceMessages;
                res.write(JSON.stringify(msgs));
                yhioeLogMsg('sent live ' + msgs.length +
                    ' device messages');
            });
        }
    } else {
        yhioeLogMsg('app.get("/n/g") failed session not found' );
    }
});

app.get('/history/:device?', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

app.post('/c/:device?', (req, res) => {
    if (!req.body.query) {
        yhioeLogMsg('app.post("/c") bad request query missing');
        return yhioeReturnResponse(res, 404,
            {error: 'query parameter missing'});
    }
    var fields = {
        query: req.body.query
    };
    return yhioeSendCmdToDevices(req, res, fields);
});

app.get('/w/s/:device?', (req, res) => {
    /* save wireless settings to all devices or one device */
    if (!(req.body.ssid || req.body.passwd)) {
        yhioeLogMsg('app.post("/w/s") bad request ssid' +
            ' or password or both must be specified');
        return yhioeReturnResponse(res, 404,
            {error: 'query parameter missing'});
    }
    var fields = {
        ssid: req.body.ssid,
        passwd: req.body.passwd,
        type: 'hostapd' /* <-- this is brain dead remove it */
    };
    if (req.body.radio) {
        fields.radio = req.body.radio
    }
    return yhioeSendCmdToDevices(req, res, fields);
});

app.get('/upgrade/:device?', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

app.get('/reboot/:device?', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

app.get('/acct', (req, res) => {
    return yhioeSendCmdToDevices(req, res);
});

/* end web facing endpoints */

var yhioeWebServiceDefaultOptions = {
    ca: null,
    key: null,
    cert: null,
    yhioeHttpServerPort: (process.env.PORT)? process.env.PORT :
        (process.env.YHIOE_ENV_DEV === 'yes')? '44433': '443',
    yhioeHttpServerHost: '127.0.0.1'
};

async function getAzureSecrets() {
    // try {
    //     process.env.FIREBASE_SECRET = await client.getSecret("FIREBASE-SECRET");
    //     process.env.FIREBASE_API_KEY = await client.getSecret("FIREBASE-API-KEY");
    //     process.env.FIREBASE_USER = await client.getSecret("FIREBASE-USER");
    //     process.env.COOKIE_KEY_1 = await client.getSecret("COOKIE-KEY-1");
    //     process.env.COOKIE_KEY_2 = await client.getSecret("COOKIE-KEY-2");
    // } catch (error) {
    //     yhioeLogMsg('error: ' + error.toString());
        process.env.FIREBASE_SECRET = process.env.AZURE_ENV_FIREBASE_SECRET;
        process.env.FIREBASE_API_KEY = process.env.AZURE_ENV_FIREBASE_API_KEY;
        process.env.FIREBASE_USER = process.env.AZURE_ENV_FIREBASE_USER;
        process.env.COOKIE_KEY_1 = process.env.AZURE_ENV_COOKIE_KEY_1;
        process.env.COOKIE_KEY_2 = process.env.AZURE_ENV_COOKIE_KEY_2;
    // }
    authcfg.firebase.user = process.env.FIREBASE_USER;
    authcfg.firebase.secret = process.env.FIREBASE_SECRET;
    authcfg.firebase.config.apiKey = process.env.FIREBASE_API_KEY;
    yhioeLogMsg('COOKIE_KEY_1: ' + process.env.COOKIE_KEY_1);
    return Promise.resolve();
};

const startServiceWeb = (opts) => {
    var srv;
    var serverOptions = {...yhioeWebServiceDefaultOptions, ...opts};
    if (!(serverOptions.cert &&
            serverOptions.key)) {
        yhioeLogMsg('Starting yhioe http broker service nnn' +
        process.env.FIREBASE_USER);
        srv = new http.createServer(app);
    } else {
        yhioeLogMsg('Starting yhioe https broker service');
        srv = new https.createServer(
            {
                cert: serverOptions.cert,
                key: serverOptions.key
            }, app);
    }
    srv.on('upgrade', yhioeHttpHandleUpgrade);
    srv.listen(process.env.PORT || serverOptions.yhioeHttpServerPort);
    yhioeModuleData.yhioeHttpServer = srv;
    return srv;
};

function startService(opts) {
    getAzureSecrets().then(() => {
        startServiceWeb(opts);
    });
}

var opts = yhioeDefaultOpts;
const HOMEDIR = require('os').homedir();

/* test config */
if (process.env.YHIOE_ENV_DEV && process.env.YHIOE_ENV_DEV === "yes") {
    var conf = {

        "ca": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/ca/ec/yh-root-ca.crt",
        "cert": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/certs/ec/web-server-cert.crt",
        "key": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/certs/ec/web-server-cert.key",
        "client_key": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/device-certs/ec/yh-2018065055-010203040506-client.key",
        "client_cert": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/device-certs/ec/yh-2018065055-010203040506-client.crt"

        /*
        "ca": HOMEDIR + "/heroku/yhioe/yh-root-ca.crt",
        "cert": HOMEDIR + "/heroku/yhioe/web-server-cert.crt",
        "key": HOMEDIR + "/heroku/yhioe/web-server-cert.key"
	    /*
        "client_key": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/device-certs/ec/yh-2018065055-010203040506-client.key",
        "client_cert": HOMEDIR + "/yh-git/yh/yhioe/yh-wireless/src/yh-host-utils/yh-backend/yh-certificates/device-certs/ec/yh-2018065055-010203040506-client.crt"
        */
    };
    var fs = require('fs');
    opts = {
        ca: fs.readFileSync(conf.ca),
        cert: fs.readFileSync(conf.cert),
        key: fs.readFileSync(conf.key)
    };
}

/* end test config */
startService(opts);
