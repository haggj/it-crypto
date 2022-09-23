"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var jose_1 = require("jose");
var crypto_1 = require("crypto");
var ENCRYPTION_ALG = "ECDH-ES";
var SIGNING_ALG = "ES256";
var RemoteUser = /** @class */ (function () {
    function RemoteUser(id, encryptionKey, verificationKey) {
        this.certificate = new Uint8Array();
        this.id = id;
        this.encryptionKey = encryptionKey;
        this.verificationKey = verificationKey;
    }
    RemoteUser.create = function () {
        return __awaiter(this, void 0, void 0, function () {
            var encryptionKeys, signingKeys;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, (0, jose_1.generateKeyPair)(ENCRYPTION_ALG)];
                    case 1:
                        encryptionKeys = _a.sent();
                        return [4 /*yield*/, (0, jose_1.generateKeyPair)(SIGNING_ALG)];
                    case 2:
                        signingKeys = _a.sent();
                        return [2 /*return*/, new RemoteUser((0, crypto_1.randomUUID)(), encryptionKeys.publicKey, signingKeys.publicKey)];
                }
            });
        });
    };
    return RemoteUser;
}());
var AuthenticatedUser = /** @class */ (function (_super) {
    __extends(AuthenticatedUser, _super);
    function AuthenticatedUser(id, encryptionKey, decryptionKey, verificationKey, signingKey) {
        var _this = _super.call(this, id, encryptionKey, verificationKey) || this;
        _this.decryptionKey = decryptionKey;
        _this.signingKey = signingKey;
        return _this;
    }
    AuthenticatedUser.prototype.signData = function (data) {
        return new jose_1.FlattenedSign(data)
            .setProtectedHeader({ alg: SIGNING_ALG })
            .sign(this.signingKey);
    };
    AuthenticatedUser.create = function () {
        return __awaiter(this, void 0, void 0, function () {
            var encryptionKeys, signingKeys;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, (0, jose_1.generateKeyPair)(ENCRYPTION_ALG)];
                    case 1:
                        encryptionKeys = _a.sent();
                        return [4 /*yield*/, (0, jose_1.generateKeyPair)(SIGNING_ALG)];
                    case 2:
                        signingKeys = _a.sent();
                        return [2 /*return*/, new AuthenticatedUser((0, crypto_1.randomUUID)(), encryptionKeys.publicKey, encryptionKeys.privateKey, signingKeys.publicKey, signingKeys.privateKey)];
                }
            });
        });
    };
    return AuthenticatedUser;
}(RemoteUser));
var EncryptionData = /** @class */ (function () {
    function EncryptionData() {
    }
    EncryptionData.prototype.asJson = function () {
        return JSON.stringify(this);
    };
    EncryptionData.prototype.asBytes = function () {
        return new TextEncoder().encode(this.asJson());
    };
    EncryptionData.fromJson = function (data) {
        return JSON.parse(data);
    };
    EncryptionData.fromBytes = function (data) {
        return EncryptionData.fromJson(new TextDecoder().decode(data));
    };
    return EncryptionData;
}());
var AccessLog = /** @class */ (function (_super) {
    __extends(AccessLog, _super);
    function AccessLog() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.data = "hallo das ist ein test";
        _this.more = 42;
        _this.shareId = (0, crypto_1.randomUUID)();
        return _this;
    }
    AccessLog.prototype.asJson = function () {
        return JSON.stringify(this);
    };
    AccessLog.prototype.asBytes = function () {
        return new TextEncoder().encode(this.asJson());
    };
    AccessLog.fromBytes = function (data) {
        return _super.fromBytes.call(this, data);
    };
    return AccessLog;
}(EncryptionData));
var AccessLogMeta = /** @class */ (function (_super) {
    __extends(AccessLogMeta, _super);
    function AccessLogMeta(shareId, owner, receivers) {
        var _this = _super.call(this) || this;
        _this.shareId = shareId;
        _this.owner = owner;
        _this.receivers = receivers;
        return _this;
    }
    AccessLogMeta.fromBytes = function (data) {
        return _super.fromBytes.call(this, data);
    };
    return AccessLogMeta;
}(EncryptionData));
var DecryptionService = /** @class */ (function () {
    function DecryptionService(sender, receiver) {
        this.sender = sender;
        this.receiver = receiver;
    }
    /*
     Decrypts AccessLogs. Only successful if the receiver was specified to access the log.
     */
    DecryptionService.prototype.decrypt = function (jwe) {
        return __awaiter(this, void 0, void 0, function () {
            var decryptionResult, jwsLogMeta, meta, jwsLog, log;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, (0, jose_1.generalDecrypt)(jwe, this.receiver.decryptionKey)];
                    case 1:
                        decryptionResult = _a.sent();
                        return [4 /*yield*/, (0, jose_1.flattenedVerify)(decryptionResult.protectedHeader.data, this.sender.verificationKey)];
                    case 2:
                        jwsLogMeta = _a.sent();
                        meta = AccessLogMeta.fromBytes(jwsLogMeta.payload);
                        return [4 /*yield*/, (0, jose_1.flattenedVerify)(JSON.parse(new TextDecoder().decode(decryptionResult.plaintext)), this.sender.verificationKey)];
                    case 3:
                        jwsLog = _a.sent();
                        log = AccessLog.fromBytes(jwsLog.payload);
                        if (meta.shareId !== log.shareId) {
                            throw new Error("IDs do not match!");
                        }
                        return [2 /*return*/, log];
                }
            });
        });
    };
    return DecryptionService;
}());
var EncryptionService = /** @class */ (function () {
    function EncryptionService(sender) {
        this.sender = sender;
    }
    /*
     Encrypt the given AccessLog for the specified receivers.
     */
    EncryptionService.prototype.encrypt = function (log, receivers) {
        return __awaiter(this, void 0, void 0, function () {
            var jwsLog, receiverIds, meta, jwsLogMeta, jwe, _i, receivers_1, receiver;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.sender.signData(log.asBytes())];
                    case 1:
                        jwsLog = _a.sent();
                        receiverIds = [];
                        receivers.forEach(function (receiver) { return receiverIds.push(receiver.id); });
                        meta = new AccessLogMeta(log.shareId, this.sender.id, receiverIds);
                        return [4 /*yield*/, this.sender.signData(meta.asBytes())];
                    case 2:
                        jwsLogMeta = _a.sent();
                        jwe = new jose_1.GeneralEncrypt(new TextEncoder().encode(JSON.stringify(jwsLog))).setProtectedHeader({ enc: "A256GCM", data: jwsLogMeta });
                        for (_i = 0, receivers_1 = receivers; _i < receivers_1.length; _i++) {
                            receiver = receivers_1[_i];
                            jwe
                                .addRecipient(receiver.encryptionKey)
                                .setUnprotectedHeader({ alg: "ECDH-ES+A256KW" });
                        }
                        return [2 /*return*/, jwe.encrypt()];
                }
            });
        });
    };
    return EncryptionService;
}());
function test() {
    return __awaiter(this, void 0, void 0, function () {
        var sender, receiver, receiver2, invalid, encService, decService, decService2, decService3, logIn, jwe, logOut, logOut2, shouldRaiseError;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, AuthenticatedUser.create()];
                case 1:
                    sender = _a.sent();
                    return [4 /*yield*/, AuthenticatedUser.create()];
                case 2:
                    receiver = _a.sent();
                    return [4 /*yield*/, AuthenticatedUser.create()];
                case 3:
                    receiver2 = _a.sent();
                    return [4 /*yield*/, AuthenticatedUser.create()];
                case 4:
                    invalid = _a.sent();
                    encService = new EncryptionService(sender);
                    decService = new DecryptionService(sender, receiver);
                    decService2 = new DecryptionService(sender, receiver2);
                    decService3 = new DecryptionService(sender, invalid);
                    logIn = new AccessLog();
                    return [4 /*yield*/, encService.encrypt(logIn, [receiver, receiver2])];
                case 5:
                    jwe = _a.sent();
                    return [4 /*yield*/, decService.decrypt(jwe)];
                case 6:
                    logOut = _a.sent();
                    return [4 /*yield*/, decService2.decrypt(jwe)];
                case 7:
                    logOut2 = _a.sent();
                    console.log(logIn);
                    console.log(logOut);
                    console.log(logOut2);
                    return [4 /*yield*/, decService3.decrypt(jwe)];
                case 8:
                    shouldRaiseError = _a.sent();
                    return [2 /*return*/];
            }
        });
    });
}
test();
