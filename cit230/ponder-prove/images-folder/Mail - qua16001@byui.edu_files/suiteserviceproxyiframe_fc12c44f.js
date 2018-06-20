﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['suiteserviceproxyiframe.mouse.js'] = (new Date()).getTime();
Function.__typeName = "Function";
Function.__class = !0;
Function.createCallback = function(n, t) {
    return function() {
        var r = arguments.length;
        if (r > 0) {
            for (var u = [], i = 0; i < r; i++) u[i] = arguments[i];
            u[r] = t;
            return n.apply(this, u)
        }
        return n.call(this, t)
    }
};
Function.prototype.bind = Function.prototype.bind || function (oThis) {
    // Polyfill
    // The bind function is an addition to ECMA-262, 5th edition; as such it may not be present in all browsers. 
    // You can partially work around this by inserting the following code at the beginning of your scripts, 
    // allowing use of much of the functionality of bind() in implementations that do not natively support it.
    // See: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/bind

    if (typeof this !== 'function') {
        // closest thing possible to the ECMAScript 5
        // internal IsCallable function
        throw new TypeError('bind(): we can only bind to functions');
    }

    var aArgs = Array.prototype.slice.call(arguments, 1),
        fToBind = this,
        fNOP = function () { },
        fBound = function () {
            return fToBind.apply(this instanceof fNOP
                    ? this
                    : oThis,
                    aArgs.concat(Array.prototype.slice.call(arguments)));
        };

    if (this.prototype) {
        // Function.prototype doesn't have a prototype property
        fNOP.prototype = this.prototype;
    }
    fBound.prototype = new fNOP();

    return fBound;
};
Function.createDelegate = function (n, t) {
    return function cd() {
        return t.apply(n, arguments)
    }
};
Function.emptyFunction = Function.emptyMethod = function() {};
Error.__typeName = "Error";
Error.__class = !0;
Error.create = function(n, t) {
    var i = new Error(n);
    i.message = n;
    if (t)
        for (var r in t) i[r] = t[r];
    i.popStackFrame();
    return i
};
Error.argument = function(n, t) {
    var r = "Sys.ArgumentException: " + (t ? t : Sys.Res.argument);
    n && (r += "\n" + String.format(Sys.Res.paramName, n));
    var i = Error.create(r, {
        name: "Sys.ArgumentException",
        paramName: n
    });
    i.popStackFrame();
    return i
};
Error.argumentNull = function(n, t) {
    var r = "Sys.ArgumentNullException: " + (t ? t : Sys.Res.argumentNull);
    n && (r += "\n" + String.format(Sys.Res.paramName, n));
    var i = Error.create(r, {
        name: "Sys.ArgumentNullException",
        paramName: n
    });
    i.popStackFrame();
    return i
};
Error.argumentOutOfRange = function(n, t, i) {
    var r = "Sys.ArgumentOutOfRangeException: " + (i ? i : Sys.Res.argumentOutOfRange);
    n && (r += "\n" + String.format(Sys.Res.paramName, n));
    typeof t != "undefined" && t !== null && (r += "\n" + String.format(Sys.Res.actualValue, t));
    var u = Error.create(r, {
        name: "Sys.ArgumentOutOfRangeException",
        paramName: n,
        actualValue: t
    });
    u.popStackFrame();
    return u
};
Error.argumentType = function(n, t, i, r) {
    var u = "Sys.ArgumentTypeException: ";
    u += r ? r : t && i ? String.format(Sys.Res.argumentTypeWithTypes, t.getName(), i.getName()) : Sys.Res.argumentType;
    n && (u += "\n" + String.format(Sys.Res.paramName, n));
    var f = Error.create(u, {
        name: "Sys.ArgumentTypeException",
        paramName: n,
        actualType: t,
        expectedType: i
    });
    f.popStackFrame();
    return f
};
Error.argumentUndefined = function(n, t) {
    var r = "Sys.ArgumentUndefinedException: " + (t ? t : Sys.Res.argumentUndefined);
    n && (r += "\n" + String.format(Sys.Res.paramName, n));
    var i = Error.create(r, {
        name: "Sys.ArgumentUndefinedException",
        paramName: n
    });
    i.popStackFrame();
    return i
};
Error.format = function(n) {
    var i = "Sys.FormatException: " + (n ? n : Sys.Res.format),
        t = Error.create(i, {
            name: "Sys.FormatException"
        });
    t.popStackFrame();
    return t
};
Error.invalidOperation = function(n) {
    var i = "Sys.InvalidOperationException: " + (n ? n : Sys.Res.invalidOperation),
        t = Error.create(i, {
            name: "Sys.InvalidOperationException"
        });
    t.popStackFrame();
    return t
};
Error.notImplemented = function(n) {
    var i = "Sys.NotImplementedException: " + (n ? n : Sys.Res.notImplemented),
        t = Error.create(i, {
            name: "Sys.NotImplementedException"
        });
    t.popStackFrame();
    return t
};
Error.parameterCount = function(n) {
    var i = "Sys.ParameterCountException: " + (n ? n : Sys.Res.parameterCount),
        t = Error.create(i, {
            name: "Sys.ParameterCountException"
        });
    t.popStackFrame();
    return t
};
Error.prototype.popStackFrame = function() {
    if (typeof this.stack != "undefined" && this.stack !== null && typeof this.fileName != "undefined" && this.fileName !== null && typeof this.lineNumber != "undefined" && this.lineNumber !== null) {
        for (var n = this.stack.split("\n"), i = n[0], u = this.fileName + ":" + this.lineNumber; typeof i != "undefined" && i !== null && i.indexOf(u) === -1;) {
            n.shift();
            i = n[0]
        }
        var r = n[1];
        if (typeof r != "undefined" && r !== null) {
            var t = r.match(/@(.*):(\d+)$/);
            if (typeof t != "undefined" && t !== null) {
                this.fileName = t[1];
                this.lineNumber = parseInt(t[2]);
                n.shift();
                this.stack = n.join("\n")
            }
        }
    }
};
Object.__typeName = "Object";
Object.__class = !0;
Object.getType = function(n) {
    var t = n.constructor;
    return !t || typeof t != "function" || !t.__typeName || t.__typeName === "Object" ? Object : t
};
Object.getTypeName = function(n) {
    return Object.getType(n).getName()
};
String.__typeName = "String";
String.__class = !0;
String.prototype.endsWith = function(n) {
    return this.substr(this.length - n.length) === n
};
String.prototype.startsWith = function(n) {
    return this.substr(0, n.length) === n
};
String.prototype.trim = function() {
    return this.replace(/^\s+|\s+$/g, "")
};
String.prototype.trimEnd = function() {
    return this.replace(/\s+$/, "")
};
String.prototype.trimStart = function() {
    return this.replace(/^\s+/, "")
};
String.format = function() {
    return String._toFormattedString(!1, arguments)
};
String._toFormattedString = function(n, t) {
    for (var u = "", e = t[0], i = 0;;) {
        var o = e.indexOf("{", i),
            f = e.indexOf("}", i);
        if (o < 0 && f < 0) {
            u += e.slice(i);
            break
        }
        if (f > 0 && (f < o || o < 0)) {
            u += e.slice(i, f + 1);
            i = f + 2;
            continue
        }
        u += e.slice(i, o);
        i = o + 1;
        if (e.charAt(i) === "{") {
            u += "{";
            i++;
            continue
        }
        if (f < 0) break;
        var s = e.substring(i, f),
            h = s.indexOf(":"),
            l = parseInt(h < 0 ? s : s.substring(0, h), 10) + 1,
            c = h < 0 ? "" : s.substring(h + 1),
            r = t[l];
        (typeof r == "undefined" || r === null) && (r = "");
        u += r.toFormattedString ? r.toFormattedString(c) : n && r.localeFormat ? r.localeFormat(c) : r.format ? r.format(c) : r.toString();
        i = f + 1
    }
    return u
};
Boolean.__typeName = "Boolean";
Boolean.__class = !0;
Boolean.parse = function(n) {
    var t = n.trim().toLowerCase();
    return t === "false" ? !1 : t === "true" ? !0 : void 0
};
Date.__typeName = "Date";
Date.__class = !0;
Number.__typeName = "Number";
Number.__class = !0;
RegExp.__typeName = "RegExp";
RegExp.__class = !0;
window || (this.window = this);
window.Type = Function;
Type.prototype.callBaseMethod = function(n, t, i) {
    var r = Sys._getBaseMethod(this, n, t);
    return i ? r.apply(n, i) : r.apply(n)
};
Type.prototype.getBaseMethod = function(n, t) {
    return Sys._getBaseMethod(this, n, t)
};
Type.prototype.getBaseType = function() {
    return typeof this.__baseType == "undefined" ? null : this.__baseType
};
Type.prototype.getInterfaces = function() {
    for (var t = [], n = this; n;) {
        var r = n.__interfaces;
        if (r)
            for (var i = 0, f = r.length; i < f; i++) {
                var u = r[i];
                Array.contains(t, u) || (t[t.length] = u)
            }
        n = n.__baseType
    }
    return t
};
Type.prototype.getName = function() {
    return typeof this.__typeName == "undefined" ? "" : this.__typeName
};
Type.prototype.implementsInterface = function(n) {
    this.resolveInheritance();
    var r = n.getName(),
        t = this.__interfaceCache;
    if (t) {
        var f = t[r];
        if (typeof f != "undefined") return f
    } else t = this.__interfaceCache = {};
    for (var i = this; i;) {
        var u = i.__interfaces;
        if (u && Array.indexOf(u, n) !== -1) return t[r] = !0;
        i = i.__baseType
    }
    return t[r] = !1
};
Type.prototype.inheritsFrom = function(n) {
    this.resolveInheritance();
    for (var t = this.__baseType; t;) {
        if (t === n) return !0;
        t = t.__baseType
    }
    return !1
};
Type.prototype.initializeBase = function(n, t) {
    this.resolveInheritance();
    this.__baseType && (t ? this.__baseType.apply(n, t) : this.__baseType.apply(n));
    return n
};
Type.prototype.isImplementedBy = function(n) {
    if (typeof n == "undefined" || n === null) return !1;
    var t = Object.getType(n);
    return !!(t.implementsInterface && t.implementsInterface(this))
};
Type.prototype.isInstanceOfType = function(n) {
    return Sys._isInstanceOfType(this, n)
};
Type.prototype.registerClass = function(n, t, i) {
    this.prototype.constructor = this;
    this.__typeName = n;
    this.__class = !0;
    if (t) {
        this.__baseType = t;
        this.__basePrototypePending = !0
    }
    if (i) {
        this.__interfaces = [];
        for (var r = 2, f = arguments.length; r < f; r++) {
            var u = arguments[r];
            this.__interfaces.push(u)
        }
    }
    return this
};
Type.prototype.registerInterface = function(n) {
    this.prototype.constructor = this;
    this.__typeName = n;
    this.__interface = !0;
    return this
};
Type.prototype.resolveInheritance = function() {
    if (this.__basePrototypePending) {
        var t = this.__baseType;
        t.resolveInheritance();
        
        if (Object.protoInheritEnabled) {
            var p = this.prototype;
            if (this.prototype["$$gta"]) {
                var pp = Object.getPrototypeOf(this.prototype);
                if (pp && Object.getPrototypeOf(pp)) {
                    p = pp;
                }
            }

            Object.setPrototypeOf(p, t.prototype);
        }
        else {
            for (var n in t.prototype) {
                var i = t.prototype[n];
                this.prototype[n] || (this.prototype[n] = i)
            }
        }
        delete this.__basePrototypePending
    }
};
Type.getRootNamespaces = function() {
    return Array.clone(Sys.__rootNamespaces)
};
Type.isClass = function(n) {
    return typeof n == "undefined" || n === null ? !1 : !! n.__class
};
Type.isInterface = function(n) {
    return typeof n == "undefined" || n === null ? !1 : !! n.__interface
};
Type.isNamespace = function(n) {
    return typeof n == "undefined" || n === null ? !1 : !! n.__namespace
};
Type.__htClasses = {};
Type.parse = function(n) {
    var t;
    if (!n) return null;
    t = Type.__htClasses[n];
    if (!t) {
        t = eval(n);
        Type.__htClasses[n] = t
    }
    return t
};
Type.registerNamespace = function(n) {
    for (var u = window, r = n.split("."), i = 0; i < r.length; i++) {
        var f = r[i],
            t = u[f];
        t || (t = u[f] = {});
        if (!t.__namespace) {
            i === 0 && n !== "Sys" && (Sys.__rootNamespaces[Sys.__rootNamespaces.length] = t);
            t.__namespace = !0;
            t.__typeName = r.slice(0, i + 1).join(".");
            t.getName = function() {
                return this.__typeName
            }
        }
        u = t
    }
};
Type.registerNamespace("Sys");
Type.registerNamespace("Sys.UI");
Type.registerNamespace("Sys.Serialization");
Type.registerNamespace("Sys.Net");
Sys.__rootNamespaces = [Sys];
Sys._isInstanceOfType = function(n, t) {
    if (typeof t == "undefined" || t === null) return !1;
    if (t instanceof n) return !0;
    var i = Object.getType(t);
    return !!(i === n) || i.inheritsFrom && i.inheritsFrom(n) || i.implementsInterface && i.implementsInterface(n)
};
Sys._getBaseMethod = function(n, t, i) {
    var u = n.getBaseType();
    if (u) {
        var r = u.prototype[i];
        return r instanceof Function ? r : null
    }
    return null
};
Sys._isDomElement = function(n) {
    var i = !1;
    if (typeof n.nodeType != "number") {
        var t = n.ownerDocument || n.document || n;
        if (t != n) {
            var r = t.defaultView || t.parentWindow;
            i = r != n
        } else i = typeof t.body == "undefined"
    }
    return !i
};
Array.__typeName = "Array";
Array.__class = !0;
Array.add = Array.enqueue = function(n, t) {
    n[n.length] = t
};
Array.addRange = function(n, t) {
    n.push.apply(n, t)
};
Array.clear = function(n) {
    n.length = 0
};
Array.clone = function(n) {
    return n.length === 1 ? [n[0]] : Array.apply(null, n)
};
Array.contains = function(n, t) {
    return Sys._indexOf(n, t) >= 0
};
Array.dequeue = function(n) {
    return n.shift()
};
Array.forEach = function(n, t, i) {
    for (var r = 0, f = n.length; r < f; r++) {
        var u = n[r];
        typeof u != "undefined" && t.call(i, u, r, n)
    }
};
Array.indexOf = function(n, t, i) {
    return Sys._indexOf(n, t, i)
};
Array.insert = function(n, t, i) {
    n.splice(t, 0, i)
};
Array.parse = function(n) {
    return n ? eval(n) : []
};
Array.remove = function(n, t) {
    var i = Sys._indexOf(n, t);
    i >= 0 && n.splice(i, 1);
    return i >= 0
};
Array.removeAt = function(n, t) {
    n.splice(t, 1)
};
Sys._indexOf = function(n, t, i) {
    if (typeof t == "undefined") return -1;
    var u = n.length;
    if (u !== 0) {
        i = +i;
        if (isNaN(i)) i = 0;
        else {
            isFinite(i) && (i = i - i % 1);
            i < 0 && (i = Math.max(0, u + i))
        }
        for (var r = i; r < u; r++)
            if (typeof n[r] != "undefined" && n[r] === t) return r
    }
    return -1
};
Sys.IDisposable = function() {};
Sys.IDisposable.prototype = {};
Sys.IDisposable.registerInterface("Sys.IDisposable");
Sys.StringBuilder = function(n) {
    this._parts = typeof n != "undefined" && n !== null && n !== "" ? [n.toString()] : [];
    this._value = {};
    this._len = 0
};
Sys.StringBuilder.prototype = {
    append: function(n) {
        this._parts[this._parts.length] = n
    },
    appendLine: function(n) {
        this._parts[this._parts.length] = typeof n == "undefined" || n === null || n === "" ? "\r\n" : n + "\r\n"
    },
    clear: function() {
        this._parts = [];
        this._value = {};
        this._len = 0
    },
    isEmpty: function() {
        return this._parts.length === 0 ? !0 : this.toString() === ""
    },
    toString: function(n) {
        n = n || "";
        var t = this._parts;
        if (this._len !== t.length) {
            this._value = {};
            this._len = t.length
        }
        var r = this._value;
        if (typeof r[n] == "undefined") {
            if (n !== "")
                for (var i = 0; i < t.length;) typeof t[i] == "undefined" || t[i] === "" || t[i] === null ? t.splice(i, 1) : i++;
            r[n] = this._parts.join(n)
        }
        return r[n]
    }
};
Sys.StringBuilder.registerClass("Sys.StringBuilder");
Sys.Browser = {};
Sys.Browser.InternetExplorer = {};
Sys.Browser.Firefox = {};
Sys.Browser.Safari = {};
Sys.Browser.Opera = {};
Sys.Browser.agent = null;
Sys.Browser.hasDebuggerStatement = !1;
Sys.Browser.name = navigator.appName;
Sys.Browser.version = parseFloat(navigator.appVersion);
Sys.Browser.documentMode = 0;
if (navigator.userAgent.indexOf(" MSIE ") > -1) {
    Sys.Browser.agent = Sys.Browser.InternetExplorer;
    Sys.Browser.version = parseFloat(navigator.userAgent.match(/MSIE (\d+\.\d+)/)[1]);
    Sys.Browser.version >= 8 && document.documentMode >= 7 && (Sys.Browser.documentMode = document.documentMode);
    Sys.Browser.hasDebuggerStatement = !0
} else if (navigator.userAgent.indexOf(" Firefox/") > -1) {
    Sys.Browser.agent = Sys.Browser.Firefox;
    Sys.Browser.version = parseFloat(navigator.userAgent.match(/Firefox\/(\d+\.\d+)/)[1]);
    Sys.Browser.name = "Firefox";
    Sys.Browser.hasDebuggerStatement = !0
} else if (navigator.userAgent.indexOf(" AppleWebKit/") > -1) {
    Sys.Browser.agent = Sys.Browser.Safari;
    Sys.Browser.version = parseFloat(navigator.userAgent.match(/AppleWebKit\/(\d+(\.\d+)?)/)[1]);
    Sys.Browser.name = "Safari"
} else navigator.userAgent.indexOf("Opera/") > -1 && (Sys.Browser.agent = Sys.Browser.Opera);
Sys.EventArgs = function() {};
Sys.EventArgs.registerClass("Sys.EventArgs");
Sys.EventArgs.Empty = new Sys.EventArgs;
Sys.CancelEventArgs = function() {
    Sys.CancelEventArgs.initializeBase(this);
    this._cancel = !1
};
Sys.CancelEventArgs.prototype = {
    get_cancel: function() {
        return this._cancel
    },
    set_cancel: function(n) {
        this._cancel = n
    }
};
Sys.CancelEventArgs.registerClass("Sys.CancelEventArgs", Sys.EventArgs);
Sys._Debug = function() {};
Sys._Debug.prototype = {
    _appendConsole: function(n) {
        typeof Debug != "undefined" && Debug.writeln;
        window.console && window.console.log && window.console.log(n);
        window.opera && window.opera.postError(n);
        window.debugService && window.debugService.trace(n)
    },
    _appendTrace: function(n) {
        var t = document.getElementById("TraceConsole");
        t && t.tagName.toUpperCase() === "TEXTAREA" && (t.value += n + "\n")
    },
    assert: function(n, t, i) {
        if (!n) {
            t = i && this.assert.caller ? String.format(Sys.Res.assertFailedCaller, t, this.assert.caller) : String.format(Sys.Res.assertFailed, t);
            confirm(String.format(Sys.Res.breakIntoDebugger, t)) && this.fail(t)
        }
    },
    clearTrace: function() {
        var n = document.getElementById("TraceConsole");
        n && n.tagName.toUpperCase() === "TEXTAREA" && (n.value = "")
    },
    fail: function(n) {
        this._appendConsole(n);
        Sys.Browser.hasDebuggerStatement && eval("debugger")
    },
    trace: function(n) {
        this._appendConsole(n);
        this._appendTrace(n)
    },
    traceDump: function(n, t) {
        var i = this._traceDump(n, t, !0)
    },
    _traceDump: function(n, t, i, r, u) {
        t = t ? t : "traceDump";
        r = r ? r : "";
        if (n === null) {
            this.trace(r + t + ": null");
            return
        }
        switch (typeof n) {
            case "undefined":
                this.trace(r + t + ": Undefined");
                break;
            case "number":
            case "string":
            case "boolean":
                this.trace(r + t + ": " + n);
                break;
            default:
                if (Date.isInstanceOfType(n) || RegExp.isInstanceOfType(n)) {
                    this.trace(r + t + ": " + n.toString());
                    break
                }
                if (u) {
                    if (Array.contains(u, n)) {
                        this.trace(r + t + ": ...");
                        return
                    }
                } else u = [];
                Array.add(u, n);
                if (n == window || n === document || window.HTMLElement && n instanceof HTMLElement || typeof n.nodeName == "string") {
                    var s = n.tagName ? n.tagName : "DomElement";
                    n.id && (s += " - " + n.id);
                    this.trace(r + t + " {" + s + "}")
                } else {
                    var h = Object.getTypeName(n);
                    this.trace(r + t + (typeof h == "string" ? " {" + h + "}" : ""));
                    if (r === "" || i) {
                        r += "    ";
                        var f, c, l, e, o;
                        if (Array.isInstanceOfType(n)) {
                            c = n.length;
                            for (f = 0; f < c; f++) this._traceDump(n[f], "[" + f + "]", i, r, u)
                        } else
                            for (e in n) {
                                o = n[e];
                                Function.isInstanceOfType(o) || this._traceDump(o, e, i, r, u)
                            }
                    }
                }
                Array.remove(u, n)
        }
    }
};
Sys._Debug.registerClass("Sys._Debug");
Sys.Debug = new Sys._Debug;
Sys.Debug.isDebug = !1;

function Sys$Enum$parse(n, t) {
    var i, r, o;
    if (t) {
        i = this.__lowerCaseValues;
        if (!i) {
            this.__lowerCaseValues = i = {};
            var s = this.prototype;
            for (var h in s) i[h.toLowerCase()] = s[h]
        }
    } else i = this.prototype; if (this.__flags) {
        for (var f = (t ? n.toLowerCase() : n).split(","), e = 0, u = f.length - 1; u >= 0; u--) {
            var c = f[u].trim();
            r = i[c];
            if (typeof r != "number") throw Error.argument("value", String.format(Sys.Res.enumInvalidValue, n.split(",")[u].trim(), this.__typeName));
            e |= r
        }
        return e
    } else {
        o = t ? n.toLowerCase() : n;
        r = i[o.trim()];
        if (typeof r != "number") throw Error.argument("value", String.format(Sys.Res.enumInvalidValue, n, this.__typeName));
        return r
    }
}

function Sys$Enum$toString(n) {
    if (typeof n == "undefined" || n === null) return this.__string;
    var f = this.prototype,
        t;
    if (this.__flags && n !== 0) {
        var i = this.__sortedValues;
        if (!i) {
            i = [];
            for (t in f) i[i.length] = {
                key: t,
                value: f[t]
            };
            i.sort(function(n, t) {
                return n.value - t.value
            });
            this.__sortedValues = i
        }
        var u = [],
            e = n;
        for (t = i.length - 1; t >= 0; t--) {
            var o = i[t],
                r = o.value;
            if (r !== 0 && (r & n) === r) {
                u[u.length] = o.key;
                e -= r;
                if (e === 0) break
            }
        }
        if (u.length && e === 0) return u.reverse().join(", ")
    } else
        for (t in f)
            if (f[t] === n) return t; return ""
}
Type.prototype.registerEnum = function(n, t) {
    for (var i in this.prototype) this[i] = this.prototype[i];
    this.__typeName = n;
    this.parse = Sys$Enum$parse;
    this.__string = this.toString();
    this.toString = Sys$Enum$toString;
    this.__flags = t;
    this.__enum = !0
};
Type.isEnum = function(n) {
    return typeof n == "undefined" || n === null ? !1 : !! n.__enum
};
Type.isFlags = function(n) {
    return typeof n == "undefined" || n === null ? !1 : !! n.__flags
};
Date._appendPreOrPostMatch = function(n, t) {
    for (var f = 0, i = !1, r = 0, e = n.length; r < e; r++) {
        var u = n.charAt(r);
        switch (u) {
            case "'":
                i ? t.append("'") : f++;
                i = !1;
                break;
            case "\\":
                i && t.append("\\");
                i = !i;
                break;
            default:
                t.append(u);
                i = !1
        }
    }
    return f
};
Date._expandFormat = function(n, t) {
    t || (t = "F");
    var i = t.length;
    if (i === 1) switch (t) {
        case "d":
            return n.ShortDatePattern;
        case "D":
            return n.LongDatePattern;
        case "t":
            return n.ShortTimePattern;
        case "T":
            return n.LongTimePattern;
        case "f":
            return n.LongDatePattern + " " + n.ShortTimePattern;
        case "F":
            return n.FullDateTimePattern;
        case "M":
        case "m":
            return n.MonthDayPattern;
        case "s":
            return n.SortableDateTimePattern;
        case "Y":
        case "y":
            return n.YearMonthPattern;
        default:
            throw Error.format(Sys.Res.formatInvalidString);
    } else i === 2 && t.charAt(0) === "%" && (t = t.charAt(1));
    return t
};
Date._expandYear = function(n, t) {
    var r = new Date,
        u = Date._getEra(r);
    if (t < 100) {
        var i = Date._getEraYear(r, n, u);
        t += i - i % 100;
        t > n.Calendar.TwoDigitYearMax && (t -= 100)
    }
    return t
};
Date._getEra = function(n, t) {
    if (!t) return 0;
    for (var r, f = n.getTime(), i = 0, u = t.length; i < u; i += 4) {
        r = t[i + 2];
        if (r === null || f >= r) return i
    }
    return 0
};
Date._getEraYear = function(n, t, i, r) {
    var u = n.getFullYear();
    !r && t.eras && (u -= t.eras[i + 3]);
    return u
};
Date._getParseRegExp = function(n, t) {
    if (n._parseRegExp) {
        if (n._parseRegExp[t]) return n._parseRegExp[t]
    } else n._parseRegExp = {};
    var u = Date._expandFormat(n, t);
    u = u.replace(/([\^\$\.\*\+\?\|\[\]\(\)\{\}])/g, "\\\\$1");
    for (var i = new Sys.StringBuilder("^"), e = [], f = 0, s = 0, h = Date._getTokenRegExp(), r;
        (r = h.exec(u)) !== null;) {
        var c = u.slice(f, r.index);
        f = h.lastIndex;
        s += Date._appendPreOrPostMatch(c, i);
        if (s % 2 == 1) {
            i.append(r[0]);
            continue
        }
        switch (r[0]) {
            case "dddd":
            case "ddd":
            case "MMMM":
            case "MMM":
            case "gg":
            case "g":
                i.append("(\\D+)");
                break;
            case "tt":
            case "t":
                i.append("(\\D*)");
                break;
            case "yyyy":
                i.append("(\\d{4})");
                break;
            case "fff":
                i.append("(\\d{3})");
                break;
            case "ff":
                i.append("(\\d{2})");
                break;
            case "f":
                i.append("(\\d)");
                break;
            case "dd":
            case "d":
            case "MM":
            case "M":
            case "yy":
            case "y":
            case "HH":
            case "H":
            case "hh":
            case "h":
            case "mm":
            case "m":
            case "ss":
            case "s":
                i.append("(\\d\\d?)");
                break;
            case "zzz":
                i.append("([+-]?\\d\\d?:\\d{2})");
                break;
            case "zz":
            case "z":
                i.append("([+-]?\\d\\d?)");
                break;
            case "/":
                i.append("(\\" + n.DateSeparator + ")")
        }
        Array.add(e, r[0])
    }
    Date._appendPreOrPostMatch(u.slice(f), i);
    i.append("$");
    var l = i.toString().replace(/\s+/g, "\\s+"),
        o = {
            regExp: l,
            groups: e
        };
    n._parseRegExp[t] = o;
    return o
};
Date._getTokenRegExp = function() {
    return /\/|dddd|ddd|dd|d|MMMM|MMM|MM|M|yyyy|yy|y|hh|h|HH|H|mm|m|ss|s|tt|t|fff|ff|f|zzz|zz|z|gg|g/g
};
Date.parseLocale = function(n) {
    return Date._parse(n, Sys.CultureInfo.CurrentCulture, arguments)
};
Date.parseInvariant = function(n) {
    return Date._parse(n, Sys.CultureInfo.InvariantCulture, arguments)
};
Date._parse = function(n, t, i) {
    for (var u, o, e, s = !1, r = 1, f = i.length; r < f; r++) {
        o = i[r];
        if (o) {
            s = !0;
            u = Date._parseExact(n, o, t);
            if (u) return u
        }
    }
    if (!s) {
        e = t._getDateTimeFormats();
        for (r = 0, f = e.length; r < f; r++) {
            u = Date._parseExact(n, e[r], t);
            if (u) return u
        }
    }
    return null
};
Date._parseExact = function(n, t, i) {
    n = n.trim();
    var h = i.dateTimeFormat,
        ft = Date._getParseRegExp(h, t),
        ut = new RegExp(ft.regExp).exec(n);
    if (ut === null) return null;
    for (var st = ft.groups, tt = null, e = null, u = null, l = null, c = null, o = 0, a, g = 0, k = 0, s = 0, d = null, nt = !1, v = 0, ct = st.length; v < ct; v++) {
        var r = ut[v + 1];
        if (r) switch (st[v]) {
            case "dd":
            case "d":
                l = parseInt(r, 10);
                if (l < 1 || l > 31) return null;
                break;
            case "MMMM":
                u = i._getMonthIndex(r);
                if (u < 0 || u > 11) return null;
                break;
            case "MMM":
                u = i._getAbbrMonthIndex(r);
                if (u < 0 || u > 11) return null;
                break;
            case "M":
            case "MM":
                u = parseInt(r, 10) - 1;
                if (u < 0 || u > 11) return null;
                break;
            case "y":
            case "yy":
                e = Date._expandYear(h, parseInt(r, 10));
                if (e < 0 || e > 9999) return null;
                break;
            case "yyyy":
                e = parseInt(r, 10);
                if (e < 0 || e > 9999) return null;
                break;
            case "h":
            case "hh":
                o = parseInt(r, 10);
                o === 12 && (o = 0);
                if (o < 0 || o > 11) return null;
                break;
            case "H":
            case "HH":
                o = parseInt(r, 10);
                if (o < 0 || o > 23) return null;
                break;
            case "m":
            case "mm":
                g = parseInt(r, 10);
                if (g < 0 || g > 59) return null;
                break;
            case "s":
            case "ss":
                k = parseInt(r, 10);
                if (k < 0 || k > 59) return null;
                break;
            case "tt":
            case "t":
                var ot = r.toUpperCase();
                nt = ot === h.PMDesignator.toUpperCase();
                if (!nt && ot !== h.AMDesignator.toUpperCase()) return null;
                break;
            case "f":
                s = parseInt(r, 10) * 100;
                if (s < 0 || s > 999) return null;
                break;
            case "ff":
                s = parseInt(r, 10) * 10;
                if (s < 0 || s > 999) return null;
                break;
            case "fff":
                s = parseInt(r, 10);
                if (s < 0 || s > 999) return null;
                break;
            case "dddd":
                c = i._getDayIndex(r);
                if (c < 0 || c > 6) return null;
                break;
            case "ddd":
                c = i._getAbbrDayIndex(r);
                if (c < 0 || c > 6) return null;
                break;
            case "zzz":
                var rt = r.split(/:/);
                if (rt.length !== 2) return null;
                a = parseInt(rt[0], 10);
                if (a < -12 || a > 13) return null;
                var y = parseInt(rt[1], 10);
                if (y < 0 || y > 59) return null;
                d = a * 60 + (r.startsWith("-") ? -y : y);
                break;
            case "z":
            case "zz":
                a = parseInt(r, 10);
                if (a < -12 || a > 13) return null;
                d = a * 60;
                break;
            case "g":
            case "gg":
                var p = r;
                if (!p || !h.eras) return null;
                p = p.toLowerCase().trim();
                for (var w = 0, ht = h.eras.length; w < ht; w += 4)
                    if (p === h.eras[w + 1].toLowerCase()) {
                        tt = w;
                        break
                    }
                if (tt === null) return null
        }
    }
    var f = new Date,
        it, b = h.Calendar.convert;
    it = b ? b.fromGregorian(f)[0] : f.getFullYear();
    e === null ? e = it : h.eras && (e += h.eras[(tt || 0) + 3]);
    u === null && (u = 0);
    l === null && (l = 1);
    if (b) {
        f = b.toGregorian(e, u, l);
        if (f === null) return null
    } else {
        f.setFullYear(e, u, l);
        if (f.getDate() !== l || c !== null && f.getDay() !== c) return null
    }
    nt && o < 12 && (o += 12);
    f.setHours(o, g, k, s);
    if (d !== null) {
        var et = f.getMinutes() - (d + f.getTimezoneOffset());
        f.setHours(f.getHours() + parseInt(et / 60, 10), et % 60)
    }
    return f
};
Date.prototype.format = function(n) {
    return this._toFormattedString(n, Sys.CultureInfo.InvariantCulture)
};
Date.prototype.localeFormat = function(n) {
    return this._toFormattedString(n, Sys.CultureInfo.CurrentCulture)
};
Date.prototype._toFormattedString = function(n, t) {
    var r = t.dateTimeFormat,
        a = r.Calendar.convert;
    if (!n || !n.length || n === "i")
        if (t && t.name.length)
            if (a) return this._toFormattedString(r.FullDateTimePattern, t);
            else {
                var w = new Date(this.getTime()),
                    nt = Date._getEra(this, r.eras);
                w.setFullYear(Date._getEraYear(this, r, nt));
                return w.toLocaleString()
            } else return this.toString();
    var l = r.eras,
        c = n === "s";
    n = Date._expandFormat(r, n);
    var i = new Sys.StringBuilder,
        u;

    function f(n) {
        return n < 10 ? "0" + n : n.toString()
    }

    function v(n) {
        return n < 10 ? "00" + n : n < 100 ? "0" + n : n.toString()
    }

    function tt(n) {
        return n < 10 ? "000" + n : n < 100 ? "00" + n : n < 1e3 ? "0" + n : n.toString()
    }
    var s, b, g = /([^d]|^)(d|dd)([^d]|$)/g;

    function k() {
        if (s || b) return s;
        s = g.test(n);
        b = !0;
        return s
    }
    var y = 0,
        p = Date._getTokenRegExp(),
        e;
    !c && a && (e = a.fromGregorian(this));
    for (;;) {
        var it = p.lastIndex,
            h = p.exec(n),
            d = n.slice(it, h ? h.index : n.length);
        y += Date._appendPreOrPostMatch(d, i);
        if (!h) break;
        if (y % 2 == 1) {
            i.append(h[0]);
            continue
        }

        function o(n, t) {
            if (e) return e[t];
            switch (t) {
                case 0:
                    return n.getFullYear();
                case 1:
                    return n.getMonth();
                case 2:
                    return n.getDate()
            }
        }
        switch (h[0]) {
            case "dddd":
                i.append(r.DayNames[this.getDay()]);
                break;
            case "ddd":
                i.append(r.AbbreviatedDayNames[this.getDay()]);
                break;
            case "dd":
                s = !0;
                i.append(f(o(this, 2)));
                break;
            case "d":
                s = !0;
                i.append(o(this, 2));
                break;
            case "MMMM":
                i.append(r.MonthGenitiveNames && k() ? r.MonthGenitiveNames[o(this, 1)] : r.MonthNames[o(this, 1)]);
                break;
            case "MMM":
                i.append(r.AbbreviatedMonthGenitiveNames && k() ? r.AbbreviatedMonthGenitiveNames[o(this, 1)] : r.AbbreviatedMonthNames[o(this, 1)]);
                break;
            case "MM":
                i.append(f(o(this, 1) + 1));
                break;
            case "M":
                i.append(o(this, 1) + 1);
                break;
            case "yyyy":
                i.append(tt(e ? e[0] : Date._getEraYear(this, r, Date._getEra(this, l), c)));
                break;
            case "yy":
                i.append(f((e ? e[0] : Date._getEraYear(this, r, Date._getEra(this, l), c)) % 100));
                break;
            case "y":
                i.append((e ? e[0] : Date._getEraYear(this, r, Date._getEra(this, l), c)) % 100);
                break;
            case "hh":
                u = this.getHours() % 12;
                u === 0 && (u = 12);
                i.append(f(u));
                break;
            case "h":
                u = this.getHours() % 12;
                u === 0 && (u = 12);
                i.append(u);
                break;
            case "HH":
                i.append(f(this.getHours()));
                break;
            case "H":
                i.append(this.getHours());
                break;
            case "mm":
                i.append(f(this.getMinutes()));
                break;
            case "m":
                i.append(this.getMinutes());
                break;
            case "ss":
                i.append(f(this.getSeconds()));
                break;
            case "s":
                i.append(this.getSeconds());
                break;
            case "tt":
                i.append(this.getHours() < 12 ? r.AMDesignator : r.PMDesignator);
                break;
            case "t":
                i.append((this.getHours() < 12 ? r.AMDesignator : r.PMDesignator).charAt(0));
                break;
            case "f":
                i.append(v(this.getMilliseconds()).charAt(0));
                break;
            case "ff":
                i.append(v(this.getMilliseconds()).substr(0, 2));
                break;
            case "fff":
                i.append(v(this.getMilliseconds()));
                break;
            case "z":
                u = this.getTimezoneOffset() / 60;
                i.append((u <= 0 ? "+" : "-") + Math.floor(Math.abs(u)));
                break;
            case "zz":
                u = this.getTimezoneOffset() / 60;
                i.append((u <= 0 ? "+" : "-") + f(Math.floor(Math.abs(u))));
                break;
            case "zzz":
                u = this.getTimezoneOffset() / 60;
                i.append((u <= 0 ? "+" : "-") + f(Math.floor(Math.abs(u))) + ":" + f(Math.abs(this.getTimezoneOffset() % 60)));
                break;
            case "g":
            case "gg":
                r.eras && i.append(r.eras[Date._getEra(this, l) + 1]);
                break;
            case "/":
                i.append(r.DateSeparator)
        }
    }
    return i.toString()
};
String.localeFormat = function() {
    return String._toFormattedString(!0, arguments)
};
Number.parseLocale = function(n) {
    return Number._parse(n, Sys.CultureInfo.CurrentCulture)
};
Number.parseInvariant = function(n) {
    return Number._parse(n, Sys.CultureInfo.InvariantCulture)
};
Number._parse = function(n, t) {
    n = n.trim();
    if (n.match(/^[+-]?infinity$/i)) return parseFloat(n);
    if (n.match(/^0x[a-f0-9]+$/i)) return parseInt(n);
    var i = t.numberFormat,
        e = Number._parseNumberNegativePattern(n, i, i.NumberNegativePattern),
        o = e[0],
        f = e[1];
    if (o === "" && i.NumberNegativePattern !== 1) {
        e = Number._parseNumberNegativePattern(n, i, 1);
        o = e[0];
        f = e[1]
    }
    o === "" && (o = "+");
    var a, u, s = f.indexOf("e");
    s < 0 && (s = f.indexOf("E"));
    if (s < 0) {
        u = f;
        a = null
    } else {
        u = f.substr(0, s);
        a = f.substr(s + 1)
    }
    var r, l, v = u.indexOf(i.NumberDecimalSeparator);
    if (v < 0) {
        r = u;
        l = null
    } else {
        r = u.substr(0, v);
        l = u.substr(v + i.NumberDecimalSeparator.length)
    }
    r = r.split(i.NumberGroupSeparator).join("");
    var y = i.NumberGroupSeparator.replace(/\u00A0/g, " ");
    i.NumberGroupSeparator !== y && (r = r.split(y).join(""));
    var h = o + r;
    l !== null && (h += "." + l);
    if (a !== null) {
        var c = Number._parseNumberNegativePattern(a, i, 1);
        c[0] === "" && (c[0] = "+");
        h += "e" + c[0] + c[1]
    }
    return h.match(/^[+-]?\d*\.?\d*(e[+-]?\d+)?$/) ? parseFloat(h) : Number.NaN
};
Number._parseNumberNegativePattern = function(n, t, i) {
    var u = t.NegativeSign,
        r = t.PositiveSign;
    switch (i) {
        case 4:
            u = " " + u;
            r = " " + r;
        case 3:
            if (n.endsWith(u)) return ["-", n.substr(0, n.length - u.length)];
            else if (n.endsWith(r)) return ["+", n.substr(0, n.length - r.length)];
            break;
        case 2:
            u += " ";
            r += " ";
        case 1:
            if (n.startsWith(u)) return ["-", n.substr(u.length)];
            else if (n.startsWith(r)) return ["+", n.substr(r.length)];
            break;
        case 0:
            if (n.startsWith("(") && n.endsWith(")")) return ["-", n.substr(1, n.length - 2)]
    }
    return ["", n]
};
Number.prototype.format = function(n) {
    return this._toFormattedString(n, Sys.CultureInfo.InvariantCulture)
};
Number.prototype.localeFormat = function(n) {
    return this._toFormattedString(n, Sys.CultureInfo.CurrentCulture)
};
Number.prototype._toFormattedString = function(n, t) {
    if (!n || n.length === 0 || n === "i") return t && t.name.length > 0 ? this.toLocaleString() : this.toString();
    var l = ["n %", "n%", "%n"],
        v = ["-n %", "-n%", "-%n"],
        y = ["(n)", "-n", "- n", "n-", "n -"],
        w = ["$n", "n$", "$ n", "n $"],
        p = ["($n)", "-$n", "$-n", "$n-", "(n$)", "-n$", "n-$", "n$-", "-n $", "-$ n", "n $-", "$ n-", "$ -n", "n- $", "($ n)", "(n $)"];

    function s(n, t, i) {
        for (var r = n.length; r < t; r++) n = i ? "0" + n : n + "0";
        return n
    }

    function h(n, t, i, r, u) {
        var a = i[0],
            v = 1,
            p = Math.pow(10, t),
            y = Math.round(n * p) / p;
        isFinite(y) || (y = n);
        n = y;
        var e = n.toString(),
            f = "",
            o, c = e.split(/e/i);
        e = c[0];
        o = c.length > 1 ? parseInt(c[1]) : 0;
        c = e.split(".");
        e = c[0];
        f = c.length > 1 ? c[1] : "";
        var w;
        if (o > 0) {
            f = s(f, o, !1);
            e += f.slice(0, o);
            f = f.substr(o)
        } else if (o < 0) {
            o = -o;
            e = s(e, o + 1, !0);
            f = e.slice(-o, e.length) + f;
            e = e.slice(0, -o)
        }
        if (t > 0) {
            f = f.length > t ? f.slice(0, t) : s(f, t, !1);
            f = u + f
        } else f = "";
        for (var h = e.length - 1, l = ""; h >= 0;) {
            if (a === 0 || a > h) return l.length > 0 ? e.slice(0, h + 1) + r + l + f : e.slice(0, h + 1) + f;
            l = l.length > 0 ? e.slice(h - a + 1, h + 1) + r + l : e.slice(h - a + 1, h + 1);
            h -= a;
            if (v < i.length) {
                a = i[v];
                v++
            }
        }
        return e.slice(0, h + 1) + r + l + f
    }
    var i = t.numberFormat,
        f = Math.abs(this);
    n || (n = "D");
    var r = -1;
    n.length > 1 && (r = parseInt(n.slice(1), 10));
    var u;
    switch (n.charAt(0)) {
        case "d":
        case "D":
            u = "n";
            r !== -1 && (f = s("" + f, r, !0));
            this < 0 && (f = -f);
            break;
        case "c":
        case "C":
            u = this < 0 ? p[i.CurrencyNegativePattern] : w[i.CurrencyPositivePattern];
            r === -1 && (r = i.CurrencyDecimalDigits);
            f = h(Math.abs(this), r, i.CurrencyGroupSizes, i.CurrencyGroupSeparator, i.CurrencyDecimalSeparator);
            break;
        case "n":
        case "N":
            u = this < 0 ? y[i.NumberNegativePattern] : "n";
            r === -1 && (r = i.NumberDecimalDigits);
            f = h(Math.abs(this), r, i.NumberGroupSizes, i.NumberGroupSeparator, i.NumberDecimalSeparator);
            break;
        case "p":
        case "P":
            u = this < 0 ? v[i.PercentNegativePattern] : l[i.PercentPositivePattern];
            r === -1 && (r = i.PercentDecimalDigits);
            f = h(Math.abs(this) * 100, r, i.PercentGroupSizes, i.PercentGroupSeparator, i.PercentDecimalSeparator);
            break;
        default:
            throw Error.format(Sys.Res.formatBadFormatSpecifier);
    }
    for (var c = /n|\$|-|%/g, e = "";;) {
        var a = c.lastIndex,
            o = c.exec(u);
        e += u.slice(a, o ? o.index : u.length);
        if (!o) break;
        switch (o[0]) {
            case "n":
                e += f;
                break;
            case "$":
                e += i.CurrencySymbol;
                break;
            case "-":
                /[1-9]/.test(f) && (e += i.NegativeSign);
                break;
            case "%":
                e += i.PercentSymbol
        }
    }
    return e
};
Sys.CultureInfo = function(n, t, i) {
    this.name = n;
    this.numberFormat = t;
    this.dateTimeFormat = i
};
Sys.CultureInfo.prototype = {
    _getDateTimeFormats: function() {
        if (!this._dateTimeFormats) {
            var n = this.dateTimeFormat;
            this._dateTimeFormats = [n.MonthDayPattern, n.YearMonthPattern, n.ShortDatePattern, n.ShortTimePattern, n.LongDatePattern, n.LongTimePattern, n.FullDateTimePattern, n.RFC1123Pattern, n.SortableDateTimePattern, n.UniversalSortableDateTimePattern]
        }
        return this._dateTimeFormats
    },
    _getIndex: function(n, t, i) {
        var u = this._toUpper(n),
            r = Array.indexOf(t, u);
        r === -1 && (r = Array.indexOf(i, u));
        return r
    },
    _getMonthIndex: function(n) {
        if (!this._upperMonths) {
            this._upperMonths = this._toUpperArray(this.dateTimeFormat.MonthNames);
            this._upperMonthsGenitive = this._toUpperArray(this.dateTimeFormat.MonthGenitiveNames)
        }
        return this._getIndex(n, this._upperMonths, this._upperMonthsGenitive)
    },
    _getAbbrMonthIndex: function(n) {
        if (!this._upperAbbrMonths) {
            this._upperAbbrMonths = this._toUpperArray(this.dateTimeFormat.AbbreviatedMonthNames);
            this._upperAbbrMonthsGenitive = this._toUpperArray(this.dateTimeFormat.AbbreviatedMonthGenitiveNames)
        }
        return this._getIndex(n, this._upperAbbrMonths, this._upperAbbrMonthsGenitive)
    },
    _getDayIndex: function(n) {
        this._upperDays || (this._upperDays = this._toUpperArray(this.dateTimeFormat.DayNames));
        return Array.indexOf(this._upperDays, this._toUpper(n))
    },
    _getAbbrDayIndex: function(n) {
        this._upperAbbrDays || (this._upperAbbrDays = this._toUpperArray(this.dateTimeFormat.AbbreviatedDayNames));
        return Array.indexOf(this._upperAbbrDays, this._toUpper(n))
    },
    _toUpperArray: function(n) {
        for (var i = [], t = 0, r = n.length; t < r; t++) i[t] = this._toUpper(n[t]);
        return i
    },
    _toUpper: function(n) {
        return n.split(" ").join(" ").toUpperCase()
    }
};
Sys.CultureInfo.registerClass("Sys.CultureInfo");
Sys.CultureInfo._parse = function(n) {
    var t = n.dateTimeFormat;
    t && !t.eras && (t.eras = n.eras);
    return new Sys.CultureInfo(n.name, n.numberFormat, t)
};
Sys.CultureInfo.InvariantCulture = Sys.CultureInfo._parse({
    name: "",
    numberFormat: {
        CurrencyDecimalDigits: 2,
        CurrencyDecimalSeparator: ".",
        IsReadOnly: !0,
        CurrencyGroupSizes: [3],
        NumberGroupSizes: [3],
        PercentGroupSizes: [3],
        CurrencyGroupSeparator: ",",
        CurrencySymbol: "¤",
        NaNSymbol: "NaN",
        CurrencyNegativePattern: 0,
        NumberNegativePattern: 1,
        PercentPositivePattern: 0,
        PercentNegativePattern: 0,
        NegativeInfinitySymbol: "-Infinity",
        NegativeSign: "-",
        NumberDecimalDigits: 2,
        NumberDecimalSeparator: ".",
        NumberGroupSeparator: ",",
        CurrencyPositivePattern: 0,
        PositiveInfinitySymbol: "Infinity",
        PositiveSign: "+",
        PercentDecimalDigits: 2,
        PercentDecimalSeparator: ".",
        PercentGroupSeparator: ",",
        PercentSymbol: "%",
        PerMilleSymbol: "‰",
        NativeDigits: ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        DigitSubstitution: 1
    },
    dateTimeFormat: {
        AMDesignator: "AM",
        Calendar: {
            MinSupportedDateTime: "@-62135568000000@",
            MaxSupportedDateTime: "@253402300799999@",
            AlgorithmType: 1,
            CalendarType: 1,
            Eras: [1],
            TwoDigitYearMax: 2029,
            IsReadOnly: !0
        },
        DateSeparator: "/",
        FirstDayOfWeek: 0,
        CalendarWeekRule: 0,
        FullDateTimePattern: "dddd, dd MMMM yyyy HH:mm:ss",
        LongDatePattern: "dddd, dd MMMM yyyy",
        LongTimePattern: "HH:mm:ss",
        MonthDayPattern: "MMMM dd",
        PMDesignator: "PM",
        RFC1123Pattern: "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
        ShortDatePattern: "MM/dd/yyyy",
        ShortTimePattern: "HH:mm",
        SortableDateTimePattern: "yyyy'-'MM'-'dd'T'HH':'mm':'ss",
        TimeSeparator: ":",
        UniversalSortableDateTimePattern: "yyyy'-'MM'-'dd HH':'mm':'ss'Z'",
        YearMonthPattern: "yyyy MMMM",
        AbbreviatedDayNames: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        ShortestDayNames: ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"],
        DayNames: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
        AbbreviatedMonthNames: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""],
        MonthNames: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", ""],
        IsReadOnly: !0,
        NativeCalendarName: "Gregorian Calendar",
        AbbreviatedMonthGenitiveNames: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""],
        MonthGenitiveNames: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", ""]
    },
    eras: [1, "A.D.", null, 0]
});
if (typeof __cultureInfo == "object") {
    Sys.CultureInfo.CurrentCulture = Sys.CultureInfo._parse(__cultureInfo);
    delete __cultureInfo
} else Sys.CultureInfo.CurrentCulture = Sys.CultureInfo._parse({
    name: "en-US",
    numberFormat: {
        CurrencyDecimalDigits: 2,
        CurrencyDecimalSeparator: ".",
        IsReadOnly: !1,
        CurrencyGroupSizes: [3],
        NumberGroupSizes: [3],
        PercentGroupSizes: [3],
        CurrencyGroupSeparator: ",",
        CurrencySymbol: "$",
        NaNSymbol: "NaN",
        CurrencyNegativePattern: 0,
        NumberNegativePattern: 1,
        PercentPositivePattern: 0,
        PercentNegativePattern: 0,
        NegativeInfinitySymbol: "-Infinity",
        NegativeSign: "-",
        NumberDecimalDigits: 2,
        NumberDecimalSeparator: ".",
        NumberGroupSeparator: ",",
        CurrencyPositivePattern: 0,
        PositiveInfinitySymbol: "Infinity",
        PositiveSign: "+",
        PercentDecimalDigits: 2,
        PercentDecimalSeparator: ".",
        PercentGroupSeparator: ",",
        PercentSymbol: "%",
        PerMilleSymbol: "‰",
        NativeDigits: ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        DigitSubstitution: 1
    },
    dateTimeFormat: {
        AMDesignator: "AM",
        Calendar: {
            MinSupportedDateTime: "@-62135568000000@",
            MaxSupportedDateTime: "@253402300799999@",
            AlgorithmType: 1,
            CalendarType: 1,
            Eras: [1],
            TwoDigitYearMax: 2029,
            IsReadOnly: !1
        },
        DateSeparator: "/",
        FirstDayOfWeek: 0,
        CalendarWeekRule: 0,
        FullDateTimePattern: "dddd, MMMM dd, yyyy h:mm:ss tt",
        LongDatePattern: "dddd, MMMM dd, yyyy",
        LongTimePattern: "h:mm:ss tt",
        MonthDayPattern: "MMMM dd",
        PMDesignator: "PM",
        RFC1123Pattern: "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
        ShortDatePattern: "M/d/yyyy",
        ShortTimePattern: "h:mm tt",
        SortableDateTimePattern: "yyyy'-'MM'-'dd'T'HH':'mm':'ss",
        TimeSeparator: ":",
        UniversalSortableDateTimePattern: "yyyy'-'MM'-'dd HH':'mm':'ss'Z'",
        YearMonthPattern: "MMMM, yyyy",
        AbbreviatedDayNames: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        ShortestDayNames: ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"],
        DayNames: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
        AbbreviatedMonthNames: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""],
        MonthNames: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", ""],
        IsReadOnly: !1,
        NativeCalendarName: "Gregorian Calendar",
        AbbreviatedMonthGenitiveNames: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""],
        MonthGenitiveNames: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", ""]
    },
    eras: [1, "A.D.", null, 0]
});
Sys.Serialization.JavaScriptSerializer = function() {};
Sys.Serialization.JavaScriptSerializer.registerClass("Sys.Serialization.JavaScriptSerializer");
Sys.Serialization.JavaScriptSerializer._charsToEscapeRegExs = [];
Sys.Serialization.JavaScriptSerializer._charsToEscape = [];
Sys.Serialization.JavaScriptSerializer._dateRegEx = new RegExp('(^|[^\\\\])\\"\\\\/Date\\((-?[0-9]+)(?:[a-zA-Z]|(?:\\+|-)[0-9]{4})?\\)\\\\/\\"', "g");
Sys.Serialization.JavaScriptSerializer._escapeChars = {};
Sys.Serialization.JavaScriptSerializer._escapeRegEx = new RegExp('["\\\\\\x00-\\x1F]', "i");
Sys.Serialization.JavaScriptSerializer._escapeRegExGlobal = new RegExp('["\\\\\\x00-\\x1F]', "g");
Sys.Serialization.JavaScriptSerializer._jsonRegEx = new RegExp("[^,:{}\\[\\]0-9.\\-+Eaeflnr-u \\n\\r\\t]", "g");
Sys.Serialization.JavaScriptSerializer._jsonStringRegEx = new RegExp('"(\\\\.|[^"\\\\])*"', "g");
Sys.Serialization.JavaScriptSerializer._serverTypeFieldName = "__type";
Sys.Serialization.JavaScriptSerializer._init = function() {
    var i = ["\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007", "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f", "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017", "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f"];
    Sys.Serialization.JavaScriptSerializer._charsToEscape[0] = "\\";
    Sys.Serialization.JavaScriptSerializer._charsToEscapeRegExs["\\"] = new RegExp("\\\\", "g");
    Sys.Serialization.JavaScriptSerializer._escapeChars["\\"] = "\\\\";
    Sys.Serialization.JavaScriptSerializer._charsToEscape[1] = '"';
    Sys.Serialization.JavaScriptSerializer._charsToEscapeRegExs['"'] = new RegExp('"', "g");
    Sys.Serialization.JavaScriptSerializer._escapeChars['"'] = '\\"';
    for (var n = 0; n < 32; n++) {
        var t = String.fromCharCode(n);
        Sys.Serialization.JavaScriptSerializer._charsToEscape[n + 2] = t;
        Sys.Serialization.JavaScriptSerializer._charsToEscapeRegExs[t] = new RegExp(t, "g");
        Sys.Serialization.JavaScriptSerializer._escapeChars[t] = i[n]
    }
};
Sys.Serialization.JavaScriptSerializer._serializeBooleanWithBuilder = function(n, t) {
    t.append(n.toString())
};
Sys.Serialization.JavaScriptSerializer._serializeNumberWithBuilder = function(n, t) {
    if (isFinite(n)) t.append(String(n));
    else throw Error.invalidOperation(Sys.Res.cannotSerializeNonFiniteNumbers);
};
Sys.Serialization.JavaScriptSerializer._serializeStringWithBuilder = function(n, t) {
    t.append('"');
    if (Sys.Serialization.JavaScriptSerializer._escapeRegEx.test(n)) {
        Sys.Serialization.JavaScriptSerializer._charsToEscape.length === 0 && Sys.Serialization.JavaScriptSerializer._init();
        if (n.length < 128) n = n.replace(Sys.Serialization.JavaScriptSerializer._escapeRegExGlobal, function(n) {
            return Sys.Serialization.JavaScriptSerializer._escapeChars[n]
        });
        else
            for (var r = 0; r < 34; r++) {
                var i = Sys.Serialization.JavaScriptSerializer._charsToEscape[r];
                n.indexOf(i) !== -1 && (n = Sys.Browser.agent === Sys.Browser.Opera || Sys.Browser.agent === Sys.Browser.FireFox ? n.split(i).join(Sys.Serialization.JavaScriptSerializer._escapeChars[i]) : n.replace(Sys.Serialization.JavaScriptSerializer._charsToEscapeRegExs[i], Sys.Serialization.JavaScriptSerializer._escapeChars[i]))
            }
    }
    t.append(n);
    t.append('"')
};
Sys.Serialization.JavaScriptSerializer._serializeWithBuilder = function(n, t, i, r) {
    var u;
    switch (typeof n) {
        case "object":
            if (n)
                if (Number.isInstanceOfType(n)) Sys.Serialization.JavaScriptSerializer._serializeNumberWithBuilder(n, t);
                else if (Boolean.isInstanceOfType(n)) Sys.Serialization.JavaScriptSerializer._serializeBooleanWithBuilder(n, t);
            else if (String.isInstanceOfType(n)) Sys.Serialization.JavaScriptSerializer._serializeStringWithBuilder(n, t);
            else if (Array.isInstanceOfType(n)) {
                t.append("[");
                for (u = 0; u < n.length; ++u) {
                    u > 0 && t.append(",");
                    Sys.Serialization.JavaScriptSerializer._serializeWithBuilder(n[u], t, !1, r)
                }
                t.append("]")
            } else {
                if (Date.isInstanceOfType(n)) {
                    t.append('"\\/Date(');
                    t.append(n.getTime());
                    t.append(')\\/"');
                    break
                }
                var f = [],
                    o = 0;
                for (var e in n)
                    if (!e.startsWith("$"))
                        if (e === Sys.Serialization.JavaScriptSerializer._serverTypeFieldName && o !== 0) {
                            f[o++] = f[0];
                            f[0] = e
                        } else f[o++] = e;
                i && f.sort();
                t.append("{");
                var h = !1;
                for (u = 0; u < o; u++) {
                    var s = n[f[u]];
                    if (typeof s != "undefined" && typeof s != "function") {
                        h ? t.append(",") : h = !0;
                        Sys.Serialization.JavaScriptSerializer._serializeWithBuilder(f[u], t, i, r);
                        t.append(":");
                        Sys.Serialization.JavaScriptSerializer._serializeWithBuilder(s, t, i, r)
                    }
                }
                t.append("}")
            } else t.append("null");
            break;
        case "number":
            Sys.Serialization.JavaScriptSerializer._serializeNumberWithBuilder(n, t);
            break;
        case "string":
            Sys.Serialization.JavaScriptSerializer._serializeStringWithBuilder(n, t);
            break;
        case "boolean":
            Sys.Serialization.JavaScriptSerializer._serializeBooleanWithBuilder(n, t);
            break;
        default:
            t.append("null")
    }
};
Sys.Serialization.JavaScriptSerializer.serialize = function(n) {
    var t = new Sys.StringBuilder;
    Sys.Serialization.JavaScriptSerializer._serializeWithBuilder(n, t, !1);
    return t.toString()
};
Sys.Serialization.JavaScriptSerializer.deserialize = function(n, t) {
    if (n.length === 0) throw Error.argument("data", Sys.Res.cannotDeserializeEmptyString);
    try {
        var i = n.replace(Sys.Serialization.JavaScriptSerializer._dateRegEx, "$1new Date($2)");
        if (t && Sys.Serialization.JavaScriptSerializer._jsonRegEx.test(i.replace(Sys.Serialization.JavaScriptSerializer._jsonStringRegEx, ""))) throw null;
        return eval("(" + i + ")")
    } catch (r) {
        throw Error.argument("data", Sys.Res.cannotDeserializeInvalidJson);
    }
};
Sys.EventHandlerList = function() {
    this._list = {}
};
Sys.EventHandlerList.prototype = {
    _addHandler: function(n, t) {
        Array.add(this._getEvent(n, !0), t)
    },
    addHandler: function(n, t) {
        this._addHandler(n, t)
    },
    _removeHandler: function(n, t) {
        var i = this._getEvent(n);
        i && Array.remove(i, t)
    },
    removeHandler: function(n, t) {
        this._removeHandler(n, t)
    },
    getHandler: function(n) {
        var t = this._getEvent(n);
        if (!t || t.length === 0) return null;
        t = Array.clone(t);
        return function(n, i) {
            for (var r = 0, u = t.length; r < u; r++) t[r](n, i)
        }
    },
    _getEvent: function(n, t) {
        if (!this._list[n]) {
            if (!t) return null;
            this._list[n] = []
        }
        return this._list[n]
    }
};
Sys.EventHandlerList.registerClass("Sys.EventHandlerList");
Sys.UI.DomEvent = function(n) {
    var t = n,
        u = this.type = t.type.toLowerCase();
    this.rawEvent = t;
    this.altKey = t.altKey;
    typeof t.button != "undefined" && (this.button = typeof t.which != "undefined" ? t.button : t.button === 4 ? Sys.UI.MouseButton.middleButton : t.button === 2 ? Sys.UI.MouseButton.rightButton : Sys.UI.MouseButton.leftButton);
    u === "keypress" ? this.charCode = t.charCode || t.keyCode : this.keyCode = t.keyCode && t.keyCode === 46 ? 127 : t.keyCode;
    this.clientX = t.clientX;
    this.clientY = t.clientY;
    this.ctrlKey = t.ctrlKey;
    this.target = t.target ? t.target : t.srcElement;
    if (!u.startsWith("key"))
        if (typeof t.offsetX != "undefined" && typeof t.offsetY != "undefined") {
            this.offsetX = t.offsetX;
            this.offsetY = t.offsetY
        } else if (this.target && this.target.nodeType !== 3 && typeof t.clientX == "number") {
        var r = Sys.UI.DomElement.getLocation(this.target),
            i = Sys.UI.DomElement._getWindow(this.target);
        this.offsetX = (i.pageXOffset || 0) + t.clientX - r.x;
        this.offsetY = (i.pageYOffset || 0) + t.clientY - r.y
    }
    this.screenX = t.screenX;
    this.screenY = t.screenY;
    this.shiftKey = t.shiftKey
};
Sys.UI.DomEvent.prototype = {
    preventDefault: function() {
        this.rawEvent.preventDefault ? this.rawEvent.preventDefault() : window.event && (this.rawEvent.returnValue = !1)
    },
    stopPropagation: function() {
        this.rawEvent.stopPropagation ? this.rawEvent.stopPropagation() : window.event && (this.rawEvent.cancelBubble = !0)
    }
};
Sys.UI.DomEvent.registerClass("Sys.UI.DomEvent");
var $addHandler = Sys.UI.DomEvent.addHandler = function(n, t, i, r) {
    n._events || (n._events = {});
    var f = n._events[t];
    f || (n._events[t] = f = []);
    var u;
    if (n.addEventListener) {
        u = function(t) {
            return i.call(n, new Sys.UI.DomEvent(t))
        };
        n.addEventListener(t, u, !1)
    } else if (n.attachEvent) {
        u = function() {
            var t = {};
            try {
                t = Sys.UI.DomElement._getWindow(n).event
            } catch (r) {}
            return i.call(n, new Sys.UI.DomEvent(t))
        };
        n.attachEvent("on" + t, u)
    }
    f[f.length] = {
        handler: i,
        browserHandler: u,
        autoRemove: r
    };
    if (r) {
        var e = n.dispose;
        if (e !== Sys.UI.DomEvent._disposeHandlers) {
            n.dispose = Sys.UI.DomEvent._disposeHandlers;
            typeof e != "undefined" && (n._chainDispose = e)
        }
    }
};
Sys.UI.DomEvent._clearHandlers = function(n, t) {
    if (n._events) {
        var f = n._events;
        for (var e in f)
            for (var u = f[e], i = u.length - 1; i >= 0; i--) {
                var r = u[i];
                (!t || r.autoRemove) && $removeHandler(n, e, r.handler)
            }
        n._events = null
    }
};
Sys.UI.DomEvent._disposeHandlers = function() {
    Sys.UI.DomEvent._clearHandlers(this, !0);
    var t = this._chainDispose,
        n = typeof t;
    if (n !== "undefined") {
        this.dispose = t;
        this._chainDispose = null;
        n === "function" && this.dispose()
    }
};
var $removeHandler = Sys.UI.DomEvent.removeHandler = function(n, t, i) {
    Sys.UI.DomEvent._removeHandler(n, t, i)
};
Sys.UI.DomEvent._removeHandler = function(n, t, i) {
    for (var f = null, u = n._events[t], r = 0, e = u.length; r < e; r++)
        if (u[r].handler === i) {
            f = u[r].browserHandler;
            break
        }
    n.removeEventListener ? n.removeEventListener(t, f, !1) : n.detachEvent && n.detachEvent("on" + t, f);
    u.splice(r, 1)
};
Sys.UI.DomElement = function() {};
Sys.UI.DomElement.registerClass("Sys.UI.DomElement");
Sys.UI.DomElement.addCssClass = function(n, t) {
    Sys.UI.DomElement.containsCssClass(n, t) || (n.className === "" ? n.className = t : n.className += " " + t)
};
Sys.UI.DomElement.containsCssClass = function(n, t) {
    return Array.contains(n.className.split(" "), t)
};
var $get = Sys.UI.DomElement.getElementById = function(n, t) {
    if (!t) return document.getElementById(n);
    if (t.getElementById) return t.getElementById(n);
    for (var u = [], f = t.childNodes, r = 0; r < f.length; r++) {
        var i = f[r];
        i.nodeType == 1 && (u[u.length] = i)
    }
    while (u.length) {
        i = u.shift();
        if (i.id == n) return i;
        f = i.childNodes;
        for (r = 0; r < f.length; r++) {
            i = f[r];
            i.nodeType == 1 && (u[u.length] = i)
        }
    }
    return null
};
Sys.UI.DomElement.getLocation = document.documentElement.getBoundingClientRect ? function(n) {
    if (n.self || n.nodeType === 9 || n === document.documentElement || n.parentNode === n.ownerDocument.documentElement) return new Sys.UI.Point(0, 0);
    var e = n.getBoundingClientRect();
    if (!e) return new Sys.UI.Point(0, 0);
    var l, u = n.ownerDocument.documentElement,
        i = Math.round(e.left) + u.scrollLeft,
        r = Math.round(e.top) + u.scrollTop;
    if (Sys.Browser.agent === Sys.Browser.InternetExplorer) {
        try {
            var f = n.ownerDocument.parentWindow.frameElement || null;
            if (f) {
                var h = f.frameBorder === "0" || f.frameBorder === "no" ? 2 : 0;
                i += h;
                r += h
            }
        } catch (c) {}
        if (Sys.Browser.version === 7 && !document.documentMode) {
            var s = document.body,
                o = s.getBoundingClientRect(),
                t = (o.right - o.left) / s.clientWidth;
            t = Math.round(t * 100);
            t = (t - t % 5) / 100;
            if (!isNaN(t) && t !== 1) {
                i = Math.round(i / t);
                r = Math.round(r / t)
            }
        }
        if ((document.documentMode || 0) < 8) {
            i -= u.clientLeft;
            r -= u.clientTop
        }
    }
    return new Sys.UI.Point(i, r)
} : Sys.Browser.agent === Sys.Browser.Safari ? function(n) {
    if (n.window && n.window === n || n.nodeType === 9) return new Sys.UI.Point(0, 0);
    for (var f = 0, u = 0, h = null, e = null, i, t = n; t; h = t, e = i, t = t.offsetParent) {
        i = Sys.UI.DomElement._getCurrentStyle(t);
        var r = t.tagName ? t.tagName.toUpperCase() : null;
        if ((t.offsetLeft || t.offsetTop) && (r !== "BODY" || !e || e.position !== "absolute")) {
            f += t.offsetLeft;
            u += t.offsetTop
        }
        if (h && Sys.Browser.version >= 3) {
            f += parseInt(i.borderLeftWidth);
            u += parseInt(i.borderTopWidth)
        }
    }
    i = Sys.UI.DomElement._getCurrentStyle(n);
    var s = i ? i.position : null;
    if (!s || s !== "absolute")
        for (t = n.parentNode; t; t = t.parentNode) {
            r = t.tagName ? t.tagName.toUpperCase() : null;
            if (r !== "BODY" && r !== "HTML" && (t.scrollLeft || t.scrollTop)) {
                f -= t.scrollLeft || 0;
                u -= t.scrollTop || 0
            }
            i = Sys.UI.DomElement._getCurrentStyle(t);
            var o = i ? i.position : null;
            if (o && o === "absolute") break
        }
    return new Sys.UI.Point(f, u)
} : function(n) {
    if (n.window && n.window === n || n.nodeType === 9) return new Sys.UI.Point(0, 0);
    for (var f = 0, u = 0, s = null, e = null, i = null, t = n; t; s = t, e = i, t = t.offsetParent) {
        var r = t.tagName ? t.tagName.toUpperCase() : null;
        i = Sys.UI.DomElement._getCurrentStyle(t);
        if ((t.offsetLeft || t.offsetTop) && !(r === "BODY" && (!e || e.position !== "absolute"))) {
            f += t.offsetLeft;
            u += t.offsetTop
        }
        if (s !== null && i) {
            if (r !== "TABLE" && r !== "TD" && r !== "HTML") {
                f += parseInt(i.borderLeftWidth) || 0;
                u += parseInt(i.borderTopWidth) || 0
            }
            if (r === "TABLE" && (i.position === "relative" || i.position === "absolute")) {
                f += parseInt(i.marginLeft) || 0;
                u += parseInt(i.marginTop) || 0
            }
        }
    }
    i = Sys.UI.DomElement._getCurrentStyle(n);
    var o = i ? i.position : null;
    if (!o || o !== "absolute")
        for (t = n.parentNode; t; t = t.parentNode) {
            r = t.tagName ? t.tagName.toUpperCase() : null;
            if (r !== "BODY" && r !== "HTML" && (t.scrollLeft || t.scrollTop)) {
                f -= t.scrollLeft || 0;
                u -= t.scrollTop || 0;
                i = Sys.UI.DomElement._getCurrentStyle(t);
                if (i) {
                    f += parseInt(i.borderLeftWidth) || 0;
                    u += parseInt(i.borderTopWidth) || 0
                }
            }
        }
    return new Sys.UI.Point(f, u)
};
Sys.UI.DomElement.removeCssClass = function(n, t) {
    var i = " " + n.className + " ",
        r = i.indexOf(" " + t + " ");
    r >= 0 && (n.className = (i.substr(0, r) + " " + i.substring(r + t.length + 1, i.length)).trim())
};
Sys.UI.DomElement._getWindow = function(n) {
    var t = n.ownerDocument || n.document || n;
    return t.defaultView || t.parentWindow
};
Sys.UI.MouseButton = function() {
    throw Error.notImplemented();
};
Sys.UI.MouseButton.prototype = {
    leftButton: 0,
    middleButton: 1,
    rightButton: 2
};
Sys.UI.MouseButton.registerEnum("Sys.UI.MouseButton");
Sys.UI.Key = function() {
    throw Error.notImplemented();
};
Sys.UI.Key.prototype = {
    backspace: 8,
    tab: 9,
    enter: 13,
    esc: 27,
    space: 32,
    pageUp: 33,
    pageDown: 34,
    end: 35,
    home: 36,
    left: 37,
    up: 38,
    right: 39,
    down: 40,
    del: 127
};
Sys.UI.Key.registerEnum("Sys.UI.Key");
Sys.UI.Point = function(n, t) {
    this.x = n;
    this.y = t
};
Sys.UI.Point.registerClass("Sys.UI.Point");
Sys.UI.Bounds = function(n, t, i, r) {
    this.x = n;
    this.y = t;
    this.height = r;
    this.width = i
};
Sys.UI.Bounds.registerClass("Sys.UI.Bounds");
var $get = function(n, t) {
    if (!t) return document.getElementById(n);
    if (t.getElementById) return t.getElementById(n);
    for (var u = [], f = t.childNodes, r = 0; r < f.length; r++) {
        var i = f[r];
        i.nodeType == 1 && (u[u.length] = i)
    }
    while (u.length) {
        i = u.shift();
        if (i.id == n) return i;
        f = i.childNodes;
        for (r = 0; r < f.length; r++) {
            i = f[r];
            i.nodeType == 1 && (u[u.length] = i)
        }
    }
    return null
};
window.XMLHttpRequest || (window.XMLHttpRequest = function() {
    for (var t = ["Msxml2.XMLHTTP.3.0", "Msxml2.XMLHTTP"], n = 0, i = t.length; n < i; n++) try {
        return new ActiveXObject(t[n])
    } catch (r) {}
    return null
});
Sys.Net.WebRequestExecutor = function() {
    this._webRequest = null;
    this._resultObject = null
};
Sys.Net.WebRequestExecutor.prototype = {
    get_webRequest: function() {
        return this._webRequest
    },
    _set_webRequest: function(n) {
        this._webRequest = n
    },
    get_started: function() {
        throw Error.notImplemented();
    },
    get_responseAvailable: function() {
        throw Error.notImplemented();
    },
    get_timedOut: function() {
        throw Error.notImplemented();
    },
    get_aborted: function() {
        throw Error.notImplemented();
    },
    get_responseData: function() {
        throw Error.notImplemented();
    },
    get_statusCode: function() {
        throw Error.notImplemented();
    },
    get_statusText: function() {
        throw Error.notImplemented();
    },
    get_xml: function() {
        throw Error.notImplemented();
    },
    get_object: function() {
        this._resultObject || (this._resultObject = Sys.Serialization.JavaScriptSerializer.deserialize(this.get_responseData()));
        return this._resultObject
    },
    executeRequest: function() {
        throw Error.notImplemented();
    },
    abort: function() {
        throw Error.notImplemented();
    },
    getResponseHeader: function() {
        throw Error.notImplemented();
    },
    getAllResponseHeaders: function() {
        throw Error.notImplemented();
    }
};
Sys.Net.WebRequestExecutor.registerClass("Sys.Net.WebRequestExecutor");
Sys.Net.XMLDOM = function(n) {
    if (window.DOMParser) try {
        var u = new window.DOMParser;
        return u.parseFromString(n, "text/xml")
    } catch (e) {} else
        for (var r = ["Msxml2.DOMDocument.3.0", "Msxml2.DOMDocument"], i = 0, f = r.length; i < f; i++) try {
            var t = new ActiveXObject(r[i]);
            t.async = !1;
            t.loadXML(n);
            t.setProperty("SelectionLanguage", "XPath");
            return t
        } catch (e) {}
    return null
};
Sys.Net.XMLHttpExecutor = function() {
    Sys.Net.XMLHttpExecutor.initializeBase(this);
    var n = this;
    this._xmlHttpRequest = null;
    this._webRequest = null;
    this._responseAvailable = !1;
    this._timedOut = !1;
    this._timer = null;
    this._aborted = !1;
    this._started = !1;
    this._onReadyStateChange = function() {
        if (n._xmlHttpRequest.readyState === 4) {
            try {
                if (typeof n._xmlHttpRequest.status == "undefined") return
            } catch (t) {
                return
            }
            n._clearTimer();
            n._responseAvailable = !0;
            try {
                n._webRequest.completed(Sys.EventArgs.Empty)
            } finally {
                if (n._xmlHttpRequest != null) {
                    n._xmlHttpRequest.onreadystatechange = Function.emptyMethod;
                    n._xmlHttpRequest = null
                }
            }
        }
    };
    this._clearTimer = function() {
        if (n._timer != null) {
            window.clearTimeout(n._timer);
            n._timer = null
        }
    };
    this._onTimeout = function() {
        if (!n._responseAvailable) {
            n._clearTimer();
            n._timedOut = !0;
            n._xmlHttpRequest.onreadystatechange = Function.emptyMethod;
            n._xmlHttpRequest.abort();
            n._webRequest.completed(Sys.EventArgs.Empty);
            n._xmlHttpRequest = null
        }
    }
};
Sys.Net.XMLHttpExecutor.prototype = {
    get_timedOut: function() {
        return this._timedOut
    },
    get_started: function() {
        return this._started
    },
    get_responseAvailable: function() {
        return this._responseAvailable
    },
    get_aborted: function() {
        return this._aborted
    },
    executeRequest: function() {
        this._webRequest = this.get_webRequest();
        var t = this._webRequest.get_body(),
            n = this._webRequest.get_headers();
        this._xmlHttpRequest = new XMLHttpRequest;
        this._xmlHttpRequest.onreadystatechange = this._onReadyStateChange;
        var u = this._webRequest.get_httpVerb();
        this._xmlHttpRequest.open(u, this._webRequest.getResolvedUrl(), !0);
        this._xmlHttpRequest.setRequestHeader("X-Requested-With", "XMLHttpRequest");
        if (n)
            for (var f in n) {
                var i = n[f];
                typeof i != "function" && this._xmlHttpRequest.setRequestHeader(f, i)
            }
        if (u.toLowerCase() === "post") {
            n !== null && n["Content-Type"] || this._xmlHttpRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            t || (t = "")
        }
        var r = this._webRequest.get_timeout();
        r > 0 && (this._timer = window.setTimeout(Function.createDelegate(this, this._onTimeout), r));
        this._xmlHttpRequest.send(t);
        this._started = !0
    },
    getResponseHeader: function(n) {
        var t;
        try {
            t = this._xmlHttpRequest.getResponseHeader(n)
        } catch (i) {}
        t || (t = "");
        return t
    },
    getAllResponseHeaders: function() {
        return this._xmlHttpRequest.getAllResponseHeaders()
    },
    get_responseData: function() {
        return this._xmlHttpRequest.responseText
    },
    get_statusCode: function() {
        var n = 0;
        try {
            n = this._xmlHttpRequest.status
        } catch (t) {}
        return n
    },
    get_statusText: function() {
        return this._xmlHttpRequest.statusText
    },
    get_xml: function() {
        var n = this._xmlHttpRequest.responseXML;
        if (n && n.documentElement) navigator.userAgent.indexOf("MSIE") !== -1 && n.setProperty("SelectionLanguage", "XPath");
        else {
            n = Sys.Net.XMLDOM(this._xmlHttpRequest.responseText);
            if (!n || !n.documentElement) return null
        }
        return n.documentElement.namespaceURI === "http://www.mozilla.org/newlayout/xml/parsererror.xml" && n.documentElement.tagName === "parsererror" ? null : n.documentElement.firstChild && n.documentElement.firstChild.tagName === "parsererror" ? null : n
    },
    abort: function() {
        if (!this._aborted && !this._responseAvailable && !this._timedOut) {
            this._aborted = !0;
            this._clearTimer();
            if (this._xmlHttpRequest && !this._responseAvailable) {
                this._xmlHttpRequest.onreadystatechange = Function.emptyMethod;
                this._xmlHttpRequest.abort();
                this._xmlHttpRequest = null;
                this._webRequest.completed(Sys.EventArgs.Empty)
            }
        }
    }
};
Sys.Net.XMLHttpExecutor.registerClass("Sys.Net.XMLHttpExecutor", Sys.Net.WebRequestExecutor);
Sys.Net._WebRequestManager = function() {
    this._defaultTimeout = 0;
    this._defaultExecutorType = "Sys.Net.XMLHttpExecutor"
};
Sys.Net._WebRequestManager.prototype = {
    add_invokingRequest: function(n) {
        this._get_eventHandlerList().addHandler("invokingRequest", n)
    },
    remove_invokingRequest: function(n) {
        this._get_eventHandlerList().removeHandler("invokingRequest", n)
    },
    add_completedRequest: function(n) {
        this._get_eventHandlerList().addHandler("completedRequest", n)
    },
    remove_completedRequest: function(n) {
        this._get_eventHandlerList().removeHandler("completedRequest", n)
    },
    _get_eventHandlerList: function() {
        this._events || (this._events = new Sys.EventHandlerList);
        return this._events
    },
    get_defaultTimeout: function() {
        return this._defaultTimeout
    },
    set_defaultTimeout: function(n) {
        this._defaultTimeout = n
    },
    get_defaultExecutorType: function() {
        return this._defaultExecutorType
    },
    set_defaultExecutorType: function(n) {
        this._defaultExecutorType = n
    },
    executeRequest: function(n) {
        var t = n.get_executor();
        if (!t) {
            var u = !1;
            try {
                var f = eval(this._defaultExecutorType);
                t = new f
            } catch (e) {
                u = !0
            }
            n.set_executor(t)
        }
        if (!t.get_aborted()) {
            var i = new Sys.Net.NetworkRequestEventArgs(n),
                r = this._get_eventHandlerList().getHandler("invokingRequest");
            r && r(this, i);
            i.get_cancel() || t.executeRequest()
        }
    }
};
Sys.Net._WebRequestManager.registerClass("Sys.Net._WebRequestManager");
Sys.Net.WebRequestManager = new Sys.Net._WebRequestManager;
Sys.Net.NetworkRequestEventArgs = function(n) {
    Sys.Net.NetworkRequestEventArgs.initializeBase(this);
    this._webRequest = n
};
Sys.Net.NetworkRequestEventArgs.prototype = {
    get_webRequest: function() {
        return this._webRequest
    }
};
Sys.Net.NetworkRequestEventArgs.registerClass("Sys.Net.NetworkRequestEventArgs", Sys.CancelEventArgs);
Sys.Net.WebRequest = function() {
    this._url = "";
    this._headers = {};
    this._body = null;
    this._userContext = null;
    this._httpVerb = null;
    this._executor = null;
    this._invokeCalled = !1;
    this._timeout = 0
};
Sys.Net.WebRequest.prototype = {
    add_completed: function(n) {
        this._get_eventHandlerList().addHandler("completed", n)
    },
    remove_completed: function(n) {
        this._get_eventHandlerList().removeHandler("completed", n)
    },
    completed: function(n) {
        var t = Sys.Net.WebRequestManager._get_eventHandlerList().getHandler("completedRequest");
        t && t(this._executor, n);
        t = this._get_eventHandlerList().getHandler("completed");
        t && t(this._executor, n)
    },
    _get_eventHandlerList: function() {
        this._events || (this._events = new Sys.EventHandlerList);
        return this._events
    },
    get_url: function() {
        return this._url
    },
    set_url: function(n) {
        this._url = n
    },
    get_headers: function() {
        return this._headers
    },
    get_httpVerb: function() {
        return this._httpVerb === null ? this._body === null ? "GET" : "POST" : this._httpVerb
    },
    set_httpVerb: function(n) {
        this._httpVerb = n
    },
    get_body: function() {
        return this._body
    },
    set_body: function(n) {
        this._body = n
    },
    get_userContext: function() {
        return this._userContext
    },
    set_userContext: function(n) {
        this._userContext = n
    },
    get_executor: function() {
        return this._executor
    },
    set_executor: function(n) {
        this._executor = n;
        this._executor._set_webRequest(this)
    },
    get_timeout: function() {
        return this._timeout === 0 ? Sys.Net.WebRequestManager.get_defaultTimeout() : this._timeout
    },
    set_timeout: function(n) {
        this._timeout = n
    },
    getResolvedUrl: function() {
        return Sys.Net.WebRequest._resolveUrl(this._url)
    },
    invoke: function() {
        Sys.Net.WebRequestManager.executeRequest(this);
        this._invokeCalled = !0
    }
};
Sys.Net.WebRequest._resolveUrl = function(n, t) {
    if (n && n.indexOf("://") !== -1) return n;
    if (!t || t.length === 0) {
        var r = document.getElementsByTagName("base")[0];
        t = r && r.href && r.href.length > 0 ? r.href : document.URL
    }
    var i = t.indexOf("?");
    i !== -1 && (t = t.substr(0, i));
    i = t.indexOf("#");
    i !== -1 && (t = t.substr(0, i));
    t = t.substr(0, t.lastIndexOf("/") + 1);
    if (!n || n.length === 0) return t;
    if (n.charAt(0) === "/") {
        var e = t.indexOf("://"),
            f = t.indexOf("/", e + 3);
        return t.substr(0, f) + n
    } else {
        var u = t.lastIndexOf("/");
        return t.substr(0, u + 1) + n
    }
};
Sys.Net.WebRequest.registerClass("Sys.Net.WebRequest");
Sys.Res = {
    argumentInteger: "Value must be an integer.",
    argumentType: "Object cannot be converted to the required type.",
    argumentNull: "Value cannot be null.",
    formatBadFormatSpecifier: "Format specifier was invalid.",
    webServiceFailedNoMsg: "The server method '{0}' failed.",
    argumentDomElement: "Value must be a DOM element.",
    actualValue: "Actual value was {0}.",
    enumInvalidValue: "'{0}' is not a valid value for enum {1}.",
    parameterCount: "Parameter count mismatch.",
    cannotDeserializeEmptyString: "Cannot deserialize empty string.",
    formatInvalidString: "Input string was not in a correct format.",
    invalidTimeout: "Value must be greater than or equal to zero.",
    argument: "Value does not fall within the expected range.",
    cannotDeserializeInvalidJson: "Cannot deserialize. The data does not correspond to valid JSON.",
    cannotSerializeNonFiniteNumbers: "Cannot serialize non finite numbers.",
    argumentUndefined: "Value cannot be undefined.",
    argumentTypeWithTypes: "Object of type '{0}' cannot be converted to type '{1}'.",
    paramName: "Parameter name: {0}",
    format: "One of the identified items was in an invalid format.",
    assertFailedCaller: "Assertion Failed: {0}\r\nat {1}",
    argumentOutOfRange: "Specified argument was out of the range of valid values.",
    webServiceTimedOut: "The server method '{0}' timed out.",
    notImplemented: "The method or operation is not implemented.",
    assertFailed: "Assertion Failed: {0}",
    invalidOperation: "Operation is not valid due to the current state of the object.",
    breakIntoDebugger: "{0}\r\n\r\nBreak into debugger?"
};
(function(n) {
    "use strict";

    function c(n, t, i) {
        n.addEventListener ? n.addEventListener(t, i, !1) : n.attachEvent && n.attachEvent("on" + t, i)
    }

    function s() {
        return typeof Sys != "undefined" && typeof Sys.Serialization != "undefined" && typeof Sys.Serialization.JavaScriptSerializer != "undefined" ? Sys.Serialization.JavaScriptSerializer : null
    }

    function o(i, o, s) {
        var c;
        if (!o) return s(i);
        if (n.JSON && n.JSON.parse) return n.JSON.parse(i);
        if (c = i.replace(e, "[]"), c = c.replace(h, "[]"), c = c.replace(u, "[]"), r.test(c)) throw t;
        if (f.test(c)) throw t;
        try {
            eval("(" + i + ")")
        } catch (l) {
            throw t;
        }
    }

    function i() {
        var n = s(),
            t;
        return n === null || typeof n.deserialize != "function" ? !1 : n.__patchVersion >= 1 ? !0 : (t = n.deserialize, n.deserialize = function(n, i) {
            return o(n, i, t)
        }, n.__patchVersion = 1, !0)
    }
    var e = new RegExp('"(\\\\.|[^"\\\\])*"', "g"),
        h = new RegExp("\\b(true|false|null)\\b", "g"),
        u = new RegExp("-?(0|([1-9]\\d*))(\\.\\d+)?([eE][+-]?\\d+)?", "g"),
        r = new RegExp("[^{:,\\[\\s](?=\\s*\\[)"),
        f = new RegExp("[^\\s\\[\\]{}:,]"),
        t = "Cannot deserialize. The data does not correspond to valid JSON.";
    i() || c(n, "load", function() {
        i()
    })
})(window);/*! Version=16.00.2403.000 */
Type.registerNamespace("_o365su");_o365su.e=function(){};_o365su.e.prototype={GET:0,POST:1,PUT:2,PATCH:3,DELETE:4};_o365su.e.registerEnum("_o365su.e",!1);_o365su.j=function(){};_o365su.j.registerInterface("_o365su.j");_o365su.i=function(){};_o365su.i.a=function(n,t,i,r,u,f,e){_o365su.i.b(n,t,i);var o=i<=r?i+u:i-u;if(i<=r&&o<=r||i>r&&o>r)window.setTimeout(function(){_o365su.i.a(n,t,o,r,u,f,e)},f);else{_o365su.i.b(n,t,r);e&&e()}};_o365su.i.b=function(n,t,i){switch(t){case 0:n.style.left=i+"px";break;case 1:n.style.right=i+"px";break;case 2:n.style.opacity=i.toString();break}};function DebugUtils(){}DebugUtils.a=function(n){DebugUtils.ConsLog&&window.console&&console.log&&console.log(n)};DebugUtils.ConsoleLog=function(n){for(var r=[],i=1;i<arguments.length;++i)r[i-1]=arguments[i];var t=null;try{var e=arguments.callee.caller.toString();t=e.match(/\s*function\s*([^\(\s]*)/)[1];t=t?"["+t+"]":"[(anonymous)]"}catch(o){t="[(unavailable)]"}n||(n="");var f=_o365su.f.e.apply(null,[n].concat(r));var u=String.format("DEBUG{0} {1}",t,f);DebugUtils.a(u)};DebugUtils.ConsoleLogIf=function(n,t){for(var r=[],i=2;i<arguments.length;++i)r[i-2]=arguments[i];n};DebugUtils.Alert=function(n){for(var f=[],u=1;u<arguments.length;++u)f[u-1]=arguments[u];for(var e=new Array(f.length),r=0;r<f.length;r++)e[r]=Sys.Serialization.JavaScriptSerializer.serialize(f[r]);var i=null;try{throw Error.create();}catch(h){i=h}var t=null;"stacktrace"in i?t=i.stacktrace.toString():"stack"in i&&(t=i.stack.toString());t&&(t="\n\nStack Trace:\n"+t);var s=String.format.apply(null,[n].concat(e));var o=String.format("{0}{1}",s,t);alert(o)};DebugUtils.AlertIf=function(n,t){for(var r=[],i=2;i<arguments.length;++i)r[i-2]=arguments[i];n};DebugUtils.Break=function(){};DebugUtils.BreakIf=function(n){n};_o365su.a=function(){};_o365su.a.a=function(n,t,i,r){_o365su.c.c(n,"addEventListener")?n.addEventListener(t,i,r):_o365su.c.c(n,"attachEvent")?n.attachEvent("on"+t,i):n["on"+t]=i};_o365su.a.b=function(n,t,i){_o365su.c.c(n,"removeEventListener")?n.removeEventListener(t,i,!1):_o365su.c.c(n,"detachEvent")?n.detachEvent("on"+t,i):n["on"+t]=null};_o365su.a.d=function(n){_o365su.c.c(n,"stopPropagation")?n.stopPropagation():n.cancelBubble=!0};_o365su.a.c=function(n){_o365su.c.c(n,"preventDefault")?n.preventDefault():n.returnValue=!1};_o365su.b=function(){};_o365su.b.ThrowOnNull=function(n,t){if(_o365su.c.d(n))throw Error.argumentNull(t);};_o365su.b.ThrowOnUndefined=function(n,t){if(_o365su.c.e(n))throw Error.argumentUndefined(t);};_o365su.b.ThrowOnNullOrUndefined=function(n,t){_o365su.b.ThrowOnUndefined(n,t);_o365su.b.ThrowOnNull(n,t)};_o365su.b.ThrowOnNullOrEmpty=function(n,t){_o365su.b.ThrowOnNullOrUndefined(n,t);if(!n.length)throw Error.argument(t);};_o365su.b.ThrowOnNullOrEmptyArray=function(n,t){_o365su.b.ThrowOnNullOrUndefined(n,t);if(!n.length)throw Error.argument(t);};_o365su.g=function(){};_o365su.g.b=function(n,t){return function(){n(t)}};_o365su.g.c=function(n,t){return function(i){n(i,t)}};_o365su.g.d=function(n,t,i){return function(){n(t,i)}};_o365su.g.a=function(n,t){try{n(t)}catch(i){}};_o365su.c=function(){};_o365su.c.c=function(n,t){return!1===_o365su.c.a(n[t])};_o365su.c.d=function(n){return n===null};_o365su.c.e=function(n){return typeof n=="undefined"};_o365su.c.a=function(n){return _o365su.c.d(n)||_o365su.c.e(n)};_o365su.c.b=function(n,t){if(_o365su.c.a(n)||!n.length)return null;var u=n.split(".");var i=t;i||(i=window.self);for(var f=u.length,r=0;r<u.length;r++)if(_o365su.c.c(i,u[r]))i=i[u[r]];else return null;return _o365su.c.a(i)?null:i};_o365su.f=function(){};_o365su.f.f=function(n,t){if(n.length>t){if(t<4){for(var f=new Sys.StringBuilder,e=0;e<t;e++)f.append(".");return f.toString()}var o=n.length-t+2;var r=n.length-o;var i=Math.floor(r/2);var u=i*2<r?i+1:i;var s=i;return n.substr(0,u)+".."+n.substr(u+o,s)}return n};_o365su.f.a=function(n){return Sys.Serialization.JavaScriptSerializer.serialize(n)};_o365su.f.b=function(n){return n?Sys.Serialization.JavaScriptSerializer.deserialize(n):n};_o365su.f.c=function(n){var t=null;t=encodeURIComponent(n);return t};_o365su.f.e=function(n){for(var r=[],i=1;i<arguments.length;++i)r[i-1]=arguments[i];for(var u=new Array(r.length),t=0;t<r.length;t++)u[t]=_o365su.f.a(r[t]);return String.format.apply(null,[n].concat(u))};_o365su.f.d=function(n,t){if(n){var i=n[t];if(i)return i.toString()}return null};_o365su.d=function(){};_o365su.d.a=function(n){if(n){var r=n.match(_o365su.d.b);if(r)for(var i=r,f=i.length,t=0;t<f;++t){var u=i[t];n=n.replace(u,_o365su.d.c)}}return n};_o365su.h=function(){};_o365su.h.b=function(n){return!!n&&(n.toLowerCase().startsWith("http://")||n.toLowerCase().startsWith("https://"))};_o365su.h.c=function(n){if(n){var t=n.indexOf("://");if(t>=0){t=n.indexOf("/",t+3);t>0&&(n=n.substr(0,t))}}return n};_o365su.h.a=function(n,t,i){var r="?";n.indexOf(r)>-1&&(r="&");return n+r+t+"="+i};_o365su.h.d=function(n){if(!n)return"";var t=encodeURI(n);return t.replace("#","%23")};DebugUtils.ConsLog=!1;_o365su.d.b=new RegExp("[a-zA-Z0-9_\\-\\.]+(@|%40|%2540)[a-zA-Z0-9_\\-\\.]+\\.[a-zA-Z]{2,5}","g");_o365su.d.c="<upn>";var msrCryptoVersion="1.01",msrCrypto=msrCrypto||function(){"use strict";function v(){function h(n){for(var t=n.length-1;t>=0;t-=1)if(n[t]+=1,n[t]>=256&&(n[t]=0),n[t])break}function c(){r=t.getVector(32);i=t.getVector(16);e=32;n=48;u=1}function l(i,r){var f,e;if(r=r||[0],r.length>n)throw new Error("Incorrect entropy or additionalEntropy length");for(r=r.concat(t.getVector(n-r.length)),i=i.concat(t.getVector((n-i.length%n)%n)),f=0;f<i.length;f+=n)e=t.xorVectors(i.slice(f,f+n),r),o(e);u=1}function o(u){for(var f=[],l=new s.aes(r),o,c;f.length<n;)h(i),o=i.slice(0,16),c=l.encrypt(o),f=f.concat(c);f=t.xorVectors(f,u);r=f.slice(0,e);i=f.slice(e)}function a(f,e){var c,l,a,v;if(f>=65536)throw new Error("too much random requested");if(u>y)throw new Error("Reseeding is required");if(e&&e.length>0){while(e.length<n)e=e.concat(t.getVector(n-e.length));o(e)}else e=t.getVector(n);for(c=[],l=new s.aes(r);c.length<f;)h(i),a=i.slice(0,i.length),v=l.encrypt(a),c=c.concat(v);return c=c.slice(0,f),o(e),u+=1,c}if(!(this instanceof v))throw new Error("create MsrcryptoPrng object with new keyword");var f=!1,r,i,e,n,u=1,y=16777216;return c(),{reseed:l,init:function(t,i){if(t.length<n)throw new Error("Initial entropy length too short");c();l(t,i);f=!0},getBytes:function(n,t){if(!f)throw new Error("can't get randomness before initialization");return a(n,t)},getNonZeroBytes:function(n,t){var r,u,i;if(!f)throw new Error("can't get randomness before initialization");for(r=[];r.length<n;)for(u=a(n,t),i=0;i<u.length;i+=1)u[i]!==0&&r.push(u[i]);return r.slice(0,n)}}}function nt(){function s(){for(var s=[],c,l,v,a,y,h=0;h<e;h+=1)s[h]=Math.floor(Math.random()*256);for(c=window.crypto||window.msCrypto,c&&typeof c.getRandomValues=="function"&&window.Uint8Array&&(l=new window.Uint8Array(e),c.getRandomValues(l),s=s.concat(Array.apply(null,l)),u=!0),v=new XMLHttpRequest,h=0;h<o.length;h+=1)try{a=v.getResponseHeader(o[h]);a&&(y=t.stringToBytes(a),s=s.concat(y))}catch(p){}u||(s=s.concat(n.splice(0,n.length)),f.startCollectors());r?i.reseed(s):i.init(s);r=!0}function h(t){for(var i=0;i<t.length;++i)n.push(t[i]);n.length>=c&&f.stopCollectors()}var e=48,n=[],c=128,l=0,i=new v,r=!1,u=!1,o=["Cookie","RedirectUri","ETag","x-ms-client-antiforgery-id","x-ms-client-request-id","x-ms-client-session-id","SubscriptionPool"],f=function(){return{startCollectors:function(){if(!this.collectorsRegistered){if(window.addEventListener)window.addEventListener("mousemove",this.MouseEventCallBack,!0),window.addEventListener("load",this.LoadTimeCallBack,!0);else if(document.attachEvent)document.attachEvent("onmousemove",this.MouseEventCallBack),document.attachEvent("onload",this.LoadTimeCallBack);else throw new Error("Can't attach events for entropy collection");this.collectorsRegistered=1}},stopCollectors:function(){this.collectorsRegistered&&(window.removeEventListener?(window.removeEventListener("mousemove",this.MouseEventCallBack,1),window.removeEventListener("load",this.LoadTimeCallBack,1)):window.detachEvent&&(window.detachEvent("onmousemove",this.MouseEventCallBack),window.detachEvent("onload",this.LoadTimeCallBack)),this.collectorsRegistered=0)},MouseEventCallBack:function(n){var t=(new Date).valueOf(),i=n.x||n.clientX||n.offsetX||0,r=n.y||n.clientY||n.offsetY||0,u=[t&255,t>>8&255,t>>16&255,t>>24&255,i&255,i>>8&255,r&255,r>>8&255];h(u)},LoadTimeCallBack:function(){var n=(new Date).valueOf(),t=[n&255,n>>8&255,n>>16&255,n>>24&255];h(t)}}}();return{init:function(){if(s(),!u&&!l)try{f.startCollectors()}catch(n){}},reseed:function(n){i.reseed(n)},read:function(n){if(!r)throw new Error("Entropy pool is not initialized.");var t=i.getBytes(n);return s(),t}}}var n={},a,r,s,c,u,i,o,p,h,f,b;n.register=function(t,i,r){n[t]||(n[t]={});var u=n[t];u[i]||(u[i]=r)};n.exists=function(t,i){return n[t]?n[t][i]?!0:!1:!1};var g=function(){if(typeof document!="undefined"){var n=document.getElementsByTagName("script");return n[n.length-1].src}return typeof self!="undefined"?self.location.href:null}(),tt=!1,w=typeof Worker!="undefined",l=typeof importScripts!="undefined",it=typeof Uint8Array!="undefined",rt=function(){try{return Object.defineProperty({},"oncomplete",{}),!0}catch(n){return!1}}(),e=w,ut=function(n){return Object.prototype.toString.call(n).replace("[object ","").replace("]","")},k=function(n,t,i,r,u){if(!rt){n[t]=i;return}var f={};r&&(f.get=r);u&&(f.set=u);Object.defineProperty(n,t,f)},d={},t=function(){function u(t,r){var f="",h,e,o,l,a,c,s,u;if(r||(r=!1),(t.pop||t.subarray)&&(t=String.fromCharCode.apply(null,t)),i)f=btoa(t);else for(u=0;u<t.length;u+=3)h=t.charCodeAt(u),e=t.charCodeAt(u+1),o=t.charCodeAt(u+2),l=h>>2,a=(h&3)<<4|e>>4,c=(e&15)<<2|o>>6,s=o&63,isNaN(e)?c=s=64:isNaN(o)&&(s=64),f=f+n.charAt(l)+n.charAt(a)+n.charAt(c)+n.charAt(s);return r?f.replace(/\+/g,"-").replace(/\//g,"_").replace(/\=/g,""):f}function f(n){if(i){for(n=n.replace(/-/g,"+").replace(/_/g,"/");n.length%4!=0;)n+="=";return atob(n)}return String.fromCharCode.apply(null,t(n))}function t(t){for(t=t.replace(/-/g,"+").replace(/_/g,"/");t.length%4!=0;)t+="=";var r=[],o,s,h,c,f,u,e,i;for(t=t.replace(/[^A-Za-z0-9\+\/\=]/g,""),i=0;i<t.length;i+=4)c=n.indexOf(t.charAt(i)),f=n.indexOf(t.charAt(i+1)),u=n.indexOf(t.charAt(i+2)),e=n.indexOf(t.charAt(i+3)),o=c<<2|f>>4,s=(f&15)<<4|u>>2,h=(u&3)<<6|e,r.push(o),u!==64&&r.push(s),e!==64&&r.push(h);return r}function e(n){return Object.prototype.toString.call(n).slice(8,-1)}function o(n,t){var r="",i,u;for(typeof t=="undefined"&&(t=!1),i=0;i<n.length;i++)t&&i%4==0&&i!==0&&(r+="-"),u=n[i].toString(16).toUpperCase(),u.length===1&&(r+="0"),r+=u;return r}function s(n){for(var i=new Array(n.length),t=0;t<i.length;t++)i[t]=n.charCodeAt(t);return i}function h(n){n=n.replace(/\-/g,"");for(var t=[];n.length>=2;)t.push(parseInt(n.substring(0,2),16)),n=n.substring(2,n.length);return t}function c(n){var i={};for(var t in n)n.hasOwnProperty(t)&&(i[t]=n[t]);return i}function l(n,i,r){var e=t(n),f=[],u;if(isNaN(i))return e;for(u=0;u<e.length;u+=i)f.push(e.slice(u,u+i));if(r)for(u=0;u<f.length;u++)f[u]=(f[u][0]<<24)+(f[u][1]<<16)+(f[u][2]<<8)+f[u][3];return f}function r(n){return[n>>>24&255,n>>>16&255,n>>>8&255,n&255]}function a(n){for(var t=[],i=0;i<n.length;i++)t=t.concat(r(n[i]));return t}function v(n,t){for(var r=Math.min(n.length,t.length),u=new Array(r),i=0;i<r;i+=1)u[i]=n[i]^t[i];return u}function y(n,t){var r,i;for(t||(t=0),r=new Array(n),i=0;i<n;i+=1)r[i]=t;return r}function p(n){if(n.pop)return n;if(n.length===1)return[n[0]];if(n.length<65536)return Array.apply(null,n);for(var r=new Array(n.length),i=0;i<n.length;i++)r[i]=n[i];return r}function w(n,t,i){if(n.indexOf)return n.indexOf(t,i);for(var r=i||0;r<n.length;r+=1)if(n[r]===t)return r;return-1}function b(n,t,i){while(n.length<i)n.push(t);return n}function k(n,t,i){while(n.length<i)n.unshift(t);return n}function d(n,t){if(n.length!==t.length)return!1;for(var i=0;i<n.length;i++)if(n[i]!==t[i])return!1;return!0}var n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",i=typeof btoa!="undefined";return{toBase64:u,base64ToString:f,base64ToBytes:t,getObjectType:e,bytesToHexString:o,stringToBytes:s,unpackData:l,hexToBytesArray:h,int32ToBytes:r,int32ArrayToBytes:a,indexOf:w,toArray:p,arraysEqual:d,clone:c,xorVectors:v,padEnd:b,padFront:k,getVector:y}}(),y=function(){function t(n){return l&&self.postMessage(n),n}return{jsCryptoRunner:function(i){var e=i.data.operationType,u,f,r;if(!n.exists(e,i.data.algorithm.name))throw new Error("unregistered algorithm.");return f=n[e][i.data.algorithm.name],r=i.data,r.operationSubType==="process"?(f(r),u=t({type:"process"})):u=t(f(r)),u}}}();return l&&(self.onmessage=function(n){if(n.data.prngSeed){var t=n.data.prngSeed;o.init(t);return}y.jsCryptoRunner(n)}),a=function(){function i(n){for(var t=[],i=0;i<n.length;i++)t[i]=n.charCodeAt(i);return t[t.length-1]===0&&t.pop(),t}function r(n){var t=n.algorithm.name.slice(0,3).toLowerCase();return t==="rsa"?"RSA":t==="ecd"?"EC":"oct"}function u(t,u){var f={},e,o;if(f.kty=r(t),f.extractable=t.extractable,u.pop)f.k=n.toBase64(u,!0);else for(e in u)u[e].pop&&(f[e]=n.toBase64(u[e],!0));return t.algorithm.namedCurve&&(f.crv=t.algorithm.namedCurve),o=JSON.stringify(f,null,"\t"),i(o)}function f(t,i,r){for(var e,o=String.fromCharCode.apply(null,t),f=JSON.parse(o),u=0;u<r.length;u+=1)e=f[r[u]],e&&(f[r[u]]=n.base64ToBytes(e));return f}var n=t;return{keyToJwk:u,jwkToKey:f}}(),r=function(){var r=function(n,t,i,r,u){function c(n){for(var nt=Math.floor(n.length/s),i,c,l,y,t,p,w,k,u,o,g,a,v,b,d=0;d<nt;d++){for(o=0;o<16;o++)b=d*s+o*4,e[o]=n[b]<<24|n[b+1]<<16|n[b+2]<<8|n[b+3];for(u=16;u<64;u++)v=e[u-15],a=e[u-2],e[u]=(a>>>17|a<<15)^(a>>>19|a<<13)^a>>>10,e[u]+=e[u-7],e[u]+=(v>>>7|v<<25)^(v>>>18|v<<14)^v>>>3,e[u]+=e[u-16];for(i=f[0],c=f[1],l=f[2],y=f[3],t=f[4],p=f[5],w=f[6],k=f[7],o=0;o<64;o++)g=k+((t>>>6|t<<26)^(t>>>11|t<<21)^(t>>>25|t<<7))+(t&p^~t&w)+r[o]+e[o],y+=g,g+=((i>>>2|i<<30)^(i>>>13|i<<19)^(i>>>22|i<<10))+(i&(c^l)^c&l),k=w,w=p,p=t,t=y,y=l,l=c,c=i,i=g;f[0]+=i&4294967295;f[1]+=c&4294967295;f[2]+=l&4294967295;f[3]+=y&4294967295;f[4]+=t&4294967295;f[5]+=p&4294967295;f[6]+=w&4294967295;f[7]+=k&4294967295}return h+=nt,n.slice(nt*s)}function v(){for(var t=new Array(256),n=0,i=0;n<8;n+=1,i+=4)t[i]=f[n]>>>24,t[i+1]=f[n]>>>16&255,t[i+2]=f[n]>>>8&255,t[i+3]=f[n]&255;return t.slice(0,u/8)}function y(n){var r=s-n.length,t,u,i;for(r<=8&&(r+=s),t=n.slice(),t.push(128),u=1;u<r-4;u++)t.push(0);return i=(n.length+h*s)*8,t.push(i>>>24&255),t.push(i>>>16&255),t.push(i>>>8&255),t.push(i&255),t}function l(n){return n.pop?n:n.length===1?[n[0]]:Array.apply(null,n)}function p(n){return o=c(l(n)),a()}function w(n){o=o.concat(l(n));o.length>=64&&(o=c(o));return}function a(){if(c(y(o)).length!==0)throw new Error("buffer.length !== 0");var n=v();return o=[],f=i.slice(),h=0,n}var s=64,f=i.slice(),e=new Array(s),o=[],h=0;return{name:n,computeHash:p,process:w,finish:a,der:t,hashLen:u,maxMessageSize:4294967295}},i,u,f,e,o,n=t.unpackData;return u=n("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q",4,1),f=n("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk",4,1),i=n("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g",4,1),e=n("MDEwDQYJYIZIAWUDBAIEBQAEIA"),o=n("MDEwDQYJYIZIAWUDBAIBBQAEIA"),{sha224:r("SHA-224",e,u,i,224),sha256:r("SHA-256",o,f,i,256)}}(),typeof n!="undefined"&&(r.hash256=function(n){if(n.operationSubType==="process"){r.sha256.process(n.buffer);return}return n.operationSubType==="finish"?r.sha256.finish():r.sha256.computeHash(n.buffer)},r.hash224=function(n){if(n.operationSubType==="process"){r.sha224.process(n.buffer);return}return n.operationSubType==="finish"?r.sha224.finish():r.sha224.computeHash(n.buffer)},n.register("digest","sha-224",r.hash224),n.register("digest","sha-256",r.hash256)),d["sha-224"]=r.sha224,d["sha-256"]=r.sha256,s=function(){var o,n,i,r,u,f,e,s,h,c;return{aes:function(l){var d,b,a,p,v,y;o||(o=t.unpackData("AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4bGR8dExEXFQsJDw0DAQcFOzk/PTMxNzUrKS8tIyEnJVtZX11TUVdVS0lPTUNBR0V7eX99c3F3dWtpb21jYWdlm5mfnZORl5WLiY+Ng4GHhbu5v72zsbe1q6mvraOhp6Xb2d/d09HX1cvJz83DwcfF+/n//fPx9/Xr6e/t4+Hn5QADBgUMDwoJGBseHRQXEhEwMzY1PD86OSgrLi0kJyIhYGNmZWxvaml4e359dHdycVBTVlVcX1pZSEtOTURHQkHAw8bFzM/Kydjb3t3U19LR8PP29fz/+vno6+7t5Ofi4aCjpqWsr6qpuLu+vbS3srGQk5aVnJ+amYiLjo2Eh4KBm5idnpeUkZKDgIWGj4yJiquora6npKGis7C1tr+8ubr7+P3+9/Tx8uPg5ebv7Onqy8jNzsfEwcLT0NXW39zZ2ltYXV5XVFFSQ0BFRk9MSUpraG1uZ2RhYnNwdXZ/fHl6Ozg9Pjc0MTIjICUmLywpKgsIDQ4HBAECExAVFh8cGRoADhwSODYkKnB+bGJIRlRa4O788tjWxMqQnoyCqKa0utvVx8nj7f/xq6W3uZOdj4E7NScpAw0fEUtFV1lzfW9hraOxv5WbiYfd08HP5ev5901DUV91e2lnPTMhLwULGRd2eGpkTkBSXAYIGhQ+MCIslpiKhK6gsrzm6Pr03tDCzEFPXVN5d2VrMT8tIwkHFRuhr72zmZeFi9HfzcPp5/X7mpSGiKKsvrDq5Pb40tzOwHp0ZmhCTF5QCgQWGDI8LiDs4vD+1NrIxpySgI6kqri2DAIQHjQ6KCZ8cmBuREpYVjc5KyUPARMdR0lbVX9xY23X2cvF7+Hz/aepu7WfkYONAA0aFzQ5LiNoZXJ/XFFGS9Ddysfk6f7zuLWir4yBlpu7tqGsj4KVmNPeycTn6v3wa2ZxfF9SRUgDDhkUNzotIG1gd3pZVENOBQgfEjE8Kya9sKeqiYSTntXYz8Lh7Pv21tvMweLv+PW+s6SpioeQnQYLHBEyPyglbmN0eVpXQE3a18DN7uP0+bK/qKWGi5yRCgcQHT4zJClib3h1VltMQWFse3ZVWE9CCQQTHj0wJyqxvKumhYifktnUw87t4Pf6t7qtoIOOmZTf0sXI6+bx/GdqfXBTXklEDwIVGDs2ISwMARYbODUiL2RpfnNQXUpH3NHGy+jl8v+0ua6jgI2alwALFh0sJzoxWFNORXR/Ymmwu6atnJeKgejj/vXEz9LZe3BtZldcQUojKDU+DwQZEsvA3dbn7PH6k5iFjr+0qaL2/eDr2tHMx66luLOCiZSfRk1QW2phfHceFQgDMjkkL42Gm5Chqre81d7DyPny7+Q9NisgERoHDGVuc3hJQl9U9/zh6tvQzcavpLmyg4iVnkdMUVprYH12HxQJAjM4JS6Mh5qRoKu2vdTfwsn48+7lPDcqIRAbBg1kb3J5SENeVQEKFxwtJjswWVJPRHV+Y2ixuqesnZaLgOni//TFztPYenFsZ1ZdQEsiKTQ/DgUYE8rB3Nfm7fD7kpmEj761qKMACRIbJC02P0hBWlNsZX53kJmCi7S9pq/Y0crD/PXu5zsyKSAfFg0Ec3phaFdeRUyrormwj4adlOPq8fjHztXcdn9kbVJbQEk+NywlGhMIAebv9P3Cy9DZrqe8tYqDmJFNRF9WaWB7cgUMFx4hKDM63dTPxvnw6+KVnIeOsbijquzl/vfIwdrTpK22v4CJkpt8dW5nWFFKQzQ9Ji8QGQIL197FzPP64eiflo2Eu7KpoEdOVVxjanF4DwYdFCsiOTCak4iBvrespdLbwMn2/+TtCgMYES4nPDVCS1BZZm90faGos7qFjJee6eD78s3E39YxOCMqFRwHDnlwa2JdVE9GY3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7FlIJatUwNqU4v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN",256,!1),n=o[0],i=o[1],r=o[2],u=o[3],f=o[4],e=o[5],s=o[6],h=o[7],c=o[8]);d=128;p=4;switch(l.length*8){case 128:b=128;a=4;v=10;break;case 192:b=192;a=6;v=12;break;case 256:b=256;a=8;v=14;break;default:throw new Error("Unsupported keyLength");}var g=function(n){var t=n[1];n[1]=n[5];n[5]=n[9];n[9]=n[13];n[13]=t;t=n[2];n[2]=n[10];n[10]=t;t=n[6];n[6]=n[14];n[14]=t;t=n[15];n[15]=n[11];n[11]=n[7];n[7]=n[3];n[3]=t},nt=function(n){var t=n[13];n[13]=n[9];n[9]=n[5];n[5]=n[1];n[1]=t;t=n[10];n[10]=n[2];n[2]=t;t=n[14];n[14]=n[6];n[6]=t;t=n[3];n[3]=n[7];n[7]=n[11];n[11]=n[15];n[15]=t},ut=function(t){var r=t[0],u=t[1],f=t[2],e=t[3],o=t[4],s=t[5],h=t[6],c=t[7],l=t[8],a=t[9],v=t[10],y=t[11],p=t[12],w=t[13],b=t[14],k=t[15];t[0]=n[r]^i[u]^f^e;t[1]=r^n[u]^i[f]^e;t[2]=r^u^n[f]^i[e];t[3]=i[r]^u^f^n[e];t[4]=n[o]^i[s]^h^c;t[5]=o^n[s]^i[h]^c;t[6]=o^s^n[h]^i[c];t[7]=i[o]^s^h^n[c];t[8]=n[l]^i[a]^v^y;t[9]=l^n[a]^i[v]^y;t[10]=l^a^n[v]^i[y];t[11]=i[l]^a^v^n[y];t[12]=n[p]^i[w]^b^k;t[13]=p^n[w]^i[b]^k;t[14]=p^w^n[b]^i[k];t[15]=i[p]^w^b^n[k]},ft=function(n){var t=n[0],i=n[1],o=n[2],s=n[3],h=n[4],c=n[5],l=n[6],a=n[7],v=n[8],y=n[9],p=n[10],w=n[11],b=n[12],k=n[13],d=n[14],g=n[15];n[0]=r[t]^f[i]^u[o]^e[s];n[1]=e[t]^r[i]^f[o]^u[s];n[2]=u[t]^e[i]^r[o]^f[s];n[3]=f[t]^u[i]^e[o]^r[s];n[4]=r[h]^f[c]^u[l]^e[a];n[5]=e[h]^r[c]^f[l]^u[a];n[6]=u[h]^e[c]^r[l]^f[a];n[7]=f[h]^u[c]^e[l]^r[a];n[8]=r[v]^f[y]^u[p]^e[w];n[9]=e[v]^r[y]^f[p]^u[w];n[10]=u[v]^e[y]^r[p]^f[w];n[11]=f[v]^u[y]^e[p]^r[w];n[12]=r[b]^f[k]^u[d]^e[g];n[13]=e[b]^r[k]^f[d]^u[g];n[14]=u[b]^e[k]^r[d]^f[g];n[15]=f[b]^u[k]^e[d]^r[g]},tt=function(n,t){return[n[0]^t[0],n[1]^t[1],n[2]^t[2],n[3]^t[3]]},w=function(n,t,i){for(var r=0;r<n.length;r+=1)n[r]^=t[r+i]},et=function(n){var t=n[0];n[0]=n[1];n[1]=n[2];n[2]=n[3];n[3]=t},k=function(n){for(var t=0;t<n.length;t+=1)n[t]=s[n[t]]},it=function(n){for(var t=0;t<n.length;t+=1)n[t]=h[n[t]]},rt=function(n,t){return[n[4*t],n[4*t+1],n[4*t+2],n[4*t+3]]},ot=function(n,t,i,r){n[4*i]=t[4*r];n[4*i+1]=t[4*r+1];n[4*i+2]=t[4*r+2];n[4*i+3]=t[4*r+3]},st=function(n){for(var i,r=[],t=0,u,f,e;t<4*a;)r.push(n[t++]);for(t=a;t<p*(v+1);)i=rt(r,t-1),t%a==0?(u=t/a,f=[c[u],0,0,0],et(i),k(i),i=tt(i,f)):a>6&&t%a==4&&k(i),e=tt(rt(r,t-a),i),ot(r,e,t,0),t+=1;return r};return y=st(l),{encrypt:function(n){var t=n,i;for(w(t,y,0),i=1;i<=v-1;i+=1)k(t),g(t),ut(t),w(t,y,4*i*p);return k(t),g(t),w(t,y,4*v*p),t},decrypt:function(n){var t=n,i;for(w(t,y,4*v*p),i=v-1;i>=1;i-=1)nt(t),it(t),w(t,y,4*i*p),ft(t);return nt(t),it(t),w(t,y,0),t},clear:function(){},keyLength:b,blockSize:d}}}}(),c=c||{},c.pkcsv7=function(n,t){var o=n.length-1>=0?n.length-1:0,i=n[o],f=i.length,s=f===t,r,u,e;if(s){for(r=[],u=0;u<t;u+=1)r.push(t);n.push(r)}else for(e=t-f&255;i.length!==t;)i.push(e)},u=function(n){function o(n){var f=[],r,t;for(i=i.concat(n),r=Math.floor(i.length/u),t=0;t<r;t++)f.push(i.slice(t*u,(t+1)*u));return i=i.slice(r*u),f}function s(i){for(var u=[],e,r=0;r<i.length;r++)e=t.xorVectors(f,i[r]),u.push(n.encrypt(e)),f=u[r];return u}function a(i){for(var u=[],e,o,r=0;r<i.length;r+=1)e=i[r].slice(0,i[r].length),o=n.decrypt(e),u.push(t.xorVectors(f,o)),f=i[r];return u}function h(){i=[];r=[];f=null}var u=n.blockSize/8,l=c.pkcsv7,e=function(n){for(var u=[],i,r,t=0;t<n.length;t+=1)for(r=n[t],i=0;i<r.length;i+=1)u.push(r[i]);return u},i=[],r=[],f;return{init:function(n){if(n.length!==u)throw new Error("Invalid iv size");f=n.slice()},encrypt:function(n){return this.processEncrypt(n),this.finishEncrypt()},processEncrypt:function(n){var t=s(o(n));r=r.concat(e(t));return},finishEncrypt:function(){var n=i.length===1?[[i[0]]]:[i],t;return l(n,u),t=r.concat(e(s(n))),h(),t},decrypt:function(n){return this.processDecrypt(n),this.finishDecrypt()},processDecrypt:function(n){var t=a(o(n));r=r.concat(e(t));return},finishDecrypt:function(){var n=r;return n=n.slice(0,n[n.length-1]*-1),h(),n}}},i=null,typeof n!="undefined"&&(u.workerEncrypt=function(n){var t;if(i||(i=u(s.aes(n.keyData)),i.init(n.algorithm.iv)),n.operationSubType==="process"){i.processEncrypt(n.buffer);return}return n.operationSubType==="finish"?(t=i.finishEncrypt(),i=null,t):(t=i.encrypt(n.buffer),i=null,t)},u.workerDecrypt=function(n){var t;if(i||(i=u(s.aes(n.keyData)),i.init(n.algorithm.iv)),n.operationSubType==="process"){i.processDecrypt(n.buffer);return}return n.operationSubType==="finish"?(t=i.finishDecrypt(),i=null,t):(t=i.decrypt(n.buffer),i=null,t)},u.generateKey=function(n){if(n.algorithm.length%8!=0)throw new Error;return{type:"keyGeneration",keyData:o.getBytes(Math.floor(n.algorithm.length/8)),keyHandle:{algorithm:n.algorithm,extractable:n.extractable,keyUsage:null||n.keyUsage,type:"secret"}}},u.importKey=function(n){var t=a.jwkToKey(n.keyData,n.algorithm,["k"]);return{type:"keyImport",keyData:t.k,keyHandle:{algorithm:n.algorithm,extractable:n.extractable||t.extractable,keyUsage:null||n.keyUsage,type:"secret"}}},u.exportKey=function(n){var t=a.keyToJwk(n.keyHandle,n.keyData);return{type:"keyExport",keyHandle:t}},n.register("importKey","aes-cbc",u.importKey),n.register("exportKey","aes-cbc",u.exportKey),n.register("generateKey","aes-cbc",u.generateKey),n.register("encrypt","aes-cbc",u.workerEncrypt),n.register("decrypt","aes-cbc",u.workerDecrypt)),o=new v,l||(p=function(){function h(){function t(t){try{if(n=y.jsCryptoRunner({data:t}),!t.operationSubType||t.operationSubType!=="process")this.onmessage({data:n})}catch(i){this.onerror({data:i.description,type:"error"})}}var n;return{postMessage:t,onmessage:null,onerror:null,terminate:function(){}}}function c(n){function u(){}function f(){}function e(n){i=n;this.result&&i({target:this})}function o(n){r=n}function s(){return i}function h(){return r}function c(t){if(t.type==="error"){if(this.onerror)this.onerror(t);return}if(t.type!=="process"){if(this.result=n(t.data),this.oncomplete)this.oncomplete({target:this});return}}var i=null,r=null,t;return t={dispatchEvent:c,addEventListener:u,removeEventListener:f,result:null},k(t,"oncomplete",null,s,e),k(t,"onerror",null,h,o),t}function tt(){function n(n){switch(n.type){case"keyGeneration":case"keyImport":case"keyDerive":return i.add(n.keyHandle,n.keyData),n.keyHandle;case"keyExport":return p(n.keyHandle);case"keyPairGeneration":return i.add(n.keyPair.publicKey.keyHandle,n.keyPair.publicKey.keyData),i.add(n.keyPair.privateKey.keyHandle,n.keyPair.privateKey.keyData),{publicKey:n.keyPair.publicKey.keyHandle,privateKey:n.keyPair.privateKey.keyHandle};default:throw new Error("Unknown key operation");}return}return c(n)}function rt(n){function i(n){return p(n)}var t=c(i);return t.process=function(t){n.operationSubType="process";n.buffer=u.toArray(t);f.continueJob(this,u.clone(n))},t.finish=function(){n.operationSubType="finish";n.buffer=[];f.continueJob(this,u.clone(n))},t.abort=function(){f.abortJob(this)},t.onabort=null,t.onprogress=null,t.algorithm=n.algorithm||null,t.key=n.keyHandle||null,t}function p(n){return it&&n.pop?new Uint8Array(n).buffer:n}function ft(n){if(n.oncomplete)n.oncomplete({target:n});else setTimeout(function(){ft(n)},b)}function d(t,i){if(!n.exists(t,i))throw new Error("unsupported algorithm");}function v(n){var t=i.lookup(n);if(!t)throw new Error("key not found");return t}function nt(n,t){for(var r,i,e={operationType:n},o=a[n],f=0;f<o.length;f+=1){if(r=l[o[f]],i=t[f],!i)if(r.required)throw new Error(r.name);else continue;if(i.subarray&&(i=u.toArray(i)),ut(i)!==r.type)throw new Error(r.name);r.name==="algorithm"&&(i.name=i.name.toLowerCase(),i.iv&&(i.iv=u.toArray(i.iv)),i.additionalData&&(i.additionalData=u.toArray(i.additionalData)));e[r.name]=i}return e}function r(n,t,i){var r=nt(n,t),u;return d(n,r.algorithm.name),r.keyHandle&&(r.keyData=v(r.keyHandle)),r.algorithm&&r.algorithm.publicKey&&(r.additionalKeyData=v(r.algorithm.publicKey)),u=i?tt(r):rt(r),(i||r.buffer||n==="deriveBits")&&f.runJob(u,r),u}var b=100,i=[],f,u,l,a,s;return i.add=function(n,t){i.push({keyHandle:n,keyData:t})},i.remove=function(n){for(var t=0;t<i.length;t++)if(i[t].keyHandle===n){i=i.splice(t,1);return}},i.lookup=function(n){for(var t=0;t<i.length;t++)if(i[t].keyHandle===n)return i[t].keyData;return null},f=function(){function b(){k(!e);for(var t=0;t<n.length;t++)if(!n[t].busy)return n[t];return null}function k(t){for(var i=n.length-1;i>=0;i-=1)n[i].isWebWorker===t&&(n[i].terminate(),n.splice(i,1))}function d(){for(var i=0,t=0;t<n.length;t++)n[t].busy||(i+=1);return i}function nt(t){n.push(t)}function r(t){for(var i=0;i<n.length;i++)if(n[i]===t){t.terminate();n.splice(i,1);return}}function u(t){for(var i=0;i<n.length;i++)if(n[i].operation===t)return n[i];return null}function f(n,i){t.push({operation:n,data:i,id:p++})}function c(n){if(n.busy=!1,n.operation=null,e)if(t.length>0){var i=t.shift();a(i.operation,i.data)}else d()>y&&r(n)}function tt(n){var r;if(e)try{r=new Worker(g);r.postMessage({prngSeed:o.getBytes(48)});r.isWebWorker=!0}catch(u){e=!1;s.forceSync=!0;r=h();r.isWebWorker=!1}else r=h(),r.isWebWorker=!1;return r.operation=n,r.busy=!1,r.onmessage=function(n){for(var e,f=r.operation,u=0;u<t.length;u++)if(t[u].operation===r.operation){e=t[u];t.splice(u,1);i(r,e.data);return}f&&n.data.type!=="process"&&(c(r),f.dispatchEvent(n))},r.onerror=function(n){var t=r.operation;c(r);t.dispatchEvent(n)},nt(r),r}function it(n){var t=u(n);t&&r(t)}function l(t,r){var u=null;if(e=w&&!s.forceSync,u=b(),e&&u===null&&n.length>=v){f(t,r);return}if(u===null&&(u=tt(t)),u===null){f(t,r);throw new Error("could not create new worker");}u.operation=t;u.busy=!0;i(u,r)}function a(n,t){var r=u(n);if(r){i(r,t);return}l(n,t)}function i(n,t){e?(n.data=t,n.postMessage(t)):setTimeout(function(){n.postMessage(t)},0)}var v=15,y=4,n=[],t=[],p=0;return{runJob:l,continueJob:a,abortJob:it}}(),u=t,l=[{name:"algorithm",type:"Object",required:!0},{name:"keyHandle",type:"Object",required:!0},{name:"buffer",type:"Array",required:!1},{name:"signature",type:"Array",required:!0},{name:"format",type:"String",required:!0},{name:"keyData",type:"Array",required:!0},{name:"extractable",type:"Boolean",required:!1},{name:"keyUsages",type:"Array",required:!1},{name:"derivedKeyType",type:"Object",required:!0},{name:"length",type:"Number",required:!1}],a={encrypt:[0,1,2],decrypt:[0,1,2],sign:[0,1,2],verify:[0,1,3,2],digest:[0,2],generateKey:[0,6,7],importKey:[4,5,0,6,7],exportKey:[0,4,1,6,7],deriveKey:[0,1,8,6,7],deriveBits:[0,1,9]},s={encrypt:function(){return r("encrypt",arguments,0)},decrypt:function(){return r("decrypt",arguments,0)},sign:function(){return r("sign",arguments,0)},verify:function(){return r("verify",arguments,0)},digest:function(){return r("digest",arguments,0)},generateKey:function(){return r("generateKey",arguments,1)},deriveKey:function(){return r("deriveKey",arguments,1)},deriveBits:function(){return r("deriveBits",arguments,0)},importKey:function(){return r("importKey",arguments,1)},exportKey:function(n,t){return r("exportKey",[t.algorithm,n,t],1)},wrapKey:function(){throw new Error("not implemented");},unwrapKey:function(){throw new Error("not implemented");}}}()),h={subtle:p,getRandomValues:function(n){for(var i=o.getBytes(n.length),t=0;t<n.length;t+=1)n[t]=i[t];return n},initPrng:function(n){var t=Object.prototype.toString.call(n);if(t!=="[object Array]"&&t!=="[object Uint8Array]")throw new Error("entropyData must be a Array or Uint8Array");f&&f.reseed(n);o.reseed(f.read(48));tt=!0},stringToBase64:t.toBase64,base64ToString:t.base64ToString},typeof cryptoMath!="undefined"&&(h.cryptoMath=cryptoMath),typeof testInterface!="undefined"&&(h.testInterface=testInterface),l||(f=f||new nt,f.init(),b=f.read(48),o.init(b)),h}();msrCrypto.subtle.forceSync = true;
// We want to use web crypto if available.
if (window.msCrypto) {
    msrCrypto.subtle = msCrypto.subtle;
};/*! Version=16.00.2403.000 */
Type.registerNamespace("O365SuiteServiceProxy");O365SuiteServiceProxy.J=function(){};O365SuiteServiceProxy.K=function(){};function MsrCryptoUtils(){}MsrCryptoUtils.ComputeSHA256=function(n,t,i,r){try{var e=MsrCryptoUtils.b(n,r);var f=new O365SuiteServiceProxy.B;f.name="SHA-256";var u=msrCrypto.subtle.digest(f,MsrCryptoUtils.c(e));u.oncomplete=function(n){if(MsrCryptoUtils.a(n,i)){var r=MsrCryptoUtils.e(n.target.result);t(msrCrypto.stringToBase64(MsrCryptoUtils.d(r,!1)))}};u.onerror=function(n){MsrCryptoUtils.a(n,i)&&i(n.target.result)}}catch(o){i(o.toString())}};MsrCryptoUtils.h=function(n,t,i,r,u){try{var o=String.format('{{ "kty": "oct", "k": "{0}", "extractable": true }}',MsrCryptoUtils.f(n));var s=MsrCryptoUtils.b(o,!1);var e=new O365SuiteServiceProxy.v;e.name="AES-CBC";var f=msrCrypto.subtle.importKey("jwk",MsrCryptoUtils.c(s),e,!0,[]);f.oncomplete=function(n){try{var s=n.target.result;var h=MsrCryptoUtils.b(msrCrypto.base64ToString(t),!1);var o=MsrCryptoUtils.b(i,!0);var f=new O365SuiteServiceProxy.w;f.iv=MsrCryptoUtils.c(h);f.name="AES-CBC";var e=msrCrypto.subtle.encrypt(f,s,MsrCryptoUtils.c(o));e.oncomplete=function(n){try{if(MsrCryptoUtils.a(n,u)){var t=MsrCryptoUtils.e(n.target.result);r(msrCrypto.stringToBase64(MsrCryptoUtils.d(t,!1)))}}catch(i){u(i.toString())}};e.onerror=function(n){MsrCryptoUtils.a(n,u)&&u(n.target.result)}}catch(c){u(c.toString())}};f.onerror=function(n){MsrCryptoUtils.a(n,u)&&u(n.target.result)}}catch(h){u(h.toString())}};MsrCryptoUtils.g=function(n,t,i,r,u){try{var o=String.format('{{ "kty": "oct", "k": "{0}", "extractable": true }}',MsrCryptoUtils.f(n));var s=MsrCryptoUtils.b(o,!1);var e=new O365SuiteServiceProxy.v;e.name="AES-CBC";var f=msrCrypto.subtle.importKey("jwk",MsrCryptoUtils.c(s),e,!0,[]);f.oncomplete=function(n){try{var s=n.target.result;var h=MsrCryptoUtils.b(msrCrypto.base64ToString(t),!1);var o=MsrCryptoUtils.b(msrCrypto.base64ToString(i),!1);var f=new O365SuiteServiceProxy.w;f.iv=MsrCryptoUtils.c(h);f.name="AES-CBC";var e=msrCrypto.subtle.decrypt(f,s,MsrCryptoUtils.c(o));e.oncomplete=function(n){try{if(MsrCryptoUtils.a(n,u)){var t=MsrCryptoUtils.e(n.target.result);r(MsrCryptoUtils.d(t,!0))}}catch(i){u(i.toString())}};e.onerror=function(n){MsrCryptoUtils.a(n,u)&&u(n.target.result)}}catch(c){u(c.toString())}};f.onerror=function(n){MsrCryptoUtils.a(n,u)&&u(n.target.result)}}catch(h){u(h.toString())}};MsrCryptoUtils.b=function(n,t){n=t?encodeURI(n):n;for(var r=new Array(n.length),i=0;i<r.length;i++)r[i]=n.charCodeAt(i);return r};MsrCryptoUtils.d=function(n,t){for(var r="",i=0;i<n.length;i++)r+=String.fromCharCode(n[i]);return t?decodeURI(r):r};MsrCryptoUtils.f=function(n){return n.replace(new RegExp("\\+","g"),"-").replace(new RegExp("/","g"),"_").replace(new RegExp("=","g"),"")};MsrCryptoUtils.c=function(n){return window.Uint8Array?new Uint8Array(n):n;return null};MsrCryptoUtils.e=function(n){if(n.pop)return n;else{var i=new Uint8Array(n);var r=i.length;if(r===1)return i[0];else{for(var u=[],t=0;t<r;t++)u[t]=i[t];return u}return null}};MsrCryptoUtils.a=function(n,t){if(n&&n.target&&n.target.result)return!0;else{t("result undefined");return!1}};O365SuiteServiceProxy.B=function(){};O365SuiteServiceProxy.B.prototype={name:null};O365SuiteServiceProxy.v=function(){};O365SuiteServiceProxy.v.prototype={name:null};O365SuiteServiceProxy.w=function(){};O365SuiteServiceProxy.w.prototype={name:null,iv:null};O365SuiteServiceProxy.E=function(){};O365SuiteServiceProxy.E.registerInterface("O365SuiteServiceProxy.E");O365SuiteServiceProxy.z=function(){};O365SuiteServiceProxy.k=function(){};O365SuiteServiceProxy.StT=function(){};O365SuiteServiceProxy.StT.prototype={session:0,suiteDataSharing:1};O365SuiteServiceProxy.StT.registerEnum("O365SuiteServiceProxy.StT",!1);O365SuiteServiceProxy.C=function(){};O365SuiteServiceProxy.C.prototype={SignedIn:1,SignedInIdp:2,NotSignedIn:3};O365SuiteServiceProxy.C.registerEnum("O365SuiteServiceProxy.C",!1);O365SuiteServiceProxy.I=function(){this.MailboxLocation=2};O365SuiteServiceProxy.p=function(){};O365SuiteServiceProxy.JQueryAdapter=function(){};O365SuiteServiceProxy.JQueryAdapter.$$cctor=function(){var n=window.self;n.MejQuery=O365SuiteServiceProxy.JQueryAdapter.a()};O365SuiteServiceProxy.JQueryAdapter.a=function(){var n=function(n){return O365SuiteServiceProxy.JQueryAPIImplementor.a(n)};n.prototype=O365SuiteServiceProxy.JQueryAPIImplementor.prototype;n.each=O365SuiteServiceProxy.JQueryAPIImplementor.each;n.parseJSON=O365SuiteServiceProxy.JQueryAPIImplementor.parseJSON;return n};O365SuiteServiceProxy.JQueryAPIImplementor=function(n){this.a=n;if(n){this[0]=n;n.jievents||(n.jievents={})}};O365SuiteServiceProxy.JQueryAPIImplementor.each=function(n,t){if(n){var i=0;if(n.length)for(var f=n;i<f.length;i++)t(i,f[i]);else{var e=n;for(var r in e){var u={key:r,value:e[r]};t(u.key,u.value)}}}};O365SuiteServiceProxy.JQueryAPIImplementor.parseJSON=function(n){return O365SuiteServiceProxy.a.j(n)};O365SuiteServiceProxy.JQueryAPIImplementor.a=function(n){if(n)if(String.isInstanceOfType(n)){var t=n;if(O365SuiteServiceProxy.JQueryAPIImplementor.b.test(t)){var i=document.createElement("Div");i.innerHTML=t;return new O365SuiteServiceProxy.JQueryAPIImplementor(i.firstChild)}else{var r=document.getElementsByTagName(t);return new O365SuiteServiceProxy.JQueryAPIImplementor(r)}}else return new O365SuiteServiceProxy.JQueryAPIImplementor(n);else return new O365SuiteServiceProxy.JQueryAPIImplementor(null)};O365SuiteServiceProxy.JQueryAPIImplementor.prototype={a:null,attr:function(n,t){if(this.a){var i=this.a;i.setAttribute(n,t)}return this},appendTo:function(n){if(n){var t=O365SuiteServiceProxy.JQueryAPIImplementor.a(n);if(t.a)if(t.a.length){var r=this;O365SuiteServiceProxy.JQueryAPIImplementor.each(t.a,function(n,t){var i=t;i.appendChild(r.a)})}else{var i=t.a;i.appendChild(this.a)}}},on:function(n,t){if(this.a&&n&&t){var u=n.split(".");var f=this;var i=function(n){var i={};i.originalEvent=n;t(i)};_o365su.a.a(this.a,u[0],i,!1);var r=this.a.jievents;r[n]=i}},off:function(n){if(this.a){var t=this.a.jievents;var i=null;t&&n in t&&(i=t[n]);var r=n.split(".");_o365su.a.b(this.a,r[0],i)}}};O365SuiteServiceProxy.m=function(){};O365SuiteServiceProxy.m.b=function(n,t,i){var f="";var u;var e=0;var c=" \"%<>'&";var h=null;if(n===h||typeof n=="undefined"||!n.length)return"";for(e=0;e<n.length;e++){var r=n.charCodeAt(e);var o=n.charAt(e);if(t&&(o==="#"||o==="?")){f+=n.substr(e);break}if(r<=127)i?f+=o:r>=97&&r<=122||r>=65&&r<=90||r>=48&&r<=57||r>=32&&r<=95&&c.indexOf(o)<0?f+=o:r<=15?f+="%0"+r.toString(16).toUpperCase():r<=127&&(f+="%"+r.toString(16).toUpperCase());else if(r<=2047){u=192|r>>6;f+="%"+u.toString(16).toUpperCase();u=128|r&63;f+="%"+u.toString(16).toUpperCase()}else if((r&64512)!=55296){u=224|r>>12;f+="%"+u.toString(16).toUpperCase();u=128|(r&4032)>>6;f+="%"+u.toString(16).toUpperCase();u=128|r&63;f+="%"+u.toString(16).toUpperCase()}else if(e<n.length-1){r=(r&1023)<<10;e++;var s=n.charCodeAt(e);r|=s&1023;r+=65536;u=240|r>>18;f+="%"+u.toString(16).toUpperCase();u=128|(r&258048)>>12;f+="%"+u.toString(16).toUpperCase();u=128|(r&4032)>>6;f+="%"+u.toString(16).toUpperCase();u=128|r&63;f+="%"+u.toString(16).toUpperCase()}}return f};O365SuiteServiceProxy.m.a=function(n){for(var f=document.cookie.split(";"),u=null,t=0;t<f.length;t++){var i=f[t];var r=i.indexOf("=");if(r!==-1&&i.substring(0,r).trim()===n){u=i.substr(r+1);break}}return u};O365SuiteServiceProxy.e=function(){};O365SuiteServiceProxy.e.a=function(n){var t=n.indexOf("://");t=n.indexOf("/",t+3);t>0&&(n=n.substr(0,t));n.substr(0,8).toLowerCase()==="https://"&&n.substr(n.length-4,4)===":443"?n=n.substr(0,n.length-4):n.substr(0,7).toLowerCase()==="http://"&&n.substr(n.length-3,3)===":80"&&(n=n.substr(0,n.length-3));return n};O365SuiteServiceProxy.e.b=function(n){n=O365SuiteServiceProxy.e.a(n);n.substr(0,8).toLowerCase()==="https://"?n=n.substr(8):n.substr(0,7).toLowerCase()==="http://"&&(n=n.substr(7));return n};O365SuiteServiceProxy.e.g=function(n){var u=null;if(typeof n=="string"){for(var r=new ArrayBuffer(n.length),f=new Uint8Array(r),i=0;i<n.length;i++)f[i]=n.charCodeAt(i)&255;var t=null;window.BlobBuilder?t=new BlobBuilder:window.MozBlobBuilder&&(t=new MozBlobBuilder);if(t){t.append(r);u=t.getBlob()}else u=r}return u};O365SuiteServiceProxy.e.f=function(n){var i="";if(n)for(var r=new Uint8Array(n),t=0;t<n.byteLength;t++)i=i+String.fromCharCode(r[t]);return i};O365SuiteServiceProxy.e.i=function(n){n.responseType="arraybuffer"};O365SuiteServiceProxy.e.h=function(){O365SuiteServiceProxy.e.e++;return O365SuiteServiceProxy.e.c+O365SuiteServiceProxy.e.e.toString()};O365SuiteServiceProxy.e.j=function(n){var i="";var t=n.indexOf("?");t>0&&(i=n.substr(t+1,n.length));return i};O365SuiteServiceProxy.e.d=function(n){var i="";var t=O365SuiteServiceProxy.e.a(n);var r=n.indexOf("?");i=r>t.length+1?n.substring(t.length+1,r):n.substring(t.length+1,n.length);return i};O365SuiteServiceProxy.e.get_emptyCallback=function(){return null};O365SuiteServiceProxy.a=function(){};O365SuiteServiceProxy.a.b=function(n){var t=null;return n===t||typeof n=="undefined"||!n.length};O365SuiteServiceProxy.a.a=function(n){var t=null;return n===t||typeof n=="undefined"};O365SuiteServiceProxy.a.d=function(n){return typeof n=="undefined"};O365SuiteServiceProxy.a.j=function(n){try{return JSON.parse(n)}catch(t){return null}};O365SuiteServiceProxy.a.h=function(){var n=window.XMLHttpRequest;if(O365SuiteServiceProxy.a.d(n))throw O365SuiteServiceProxy.a.c("Browser not supported",-2003);return new XMLHttpRequest};O365SuiteServiceProxy.a.k=function(n,t){if(!O365SuiteServiceProxy.a.i(n))throw O365SuiteServiceProxy.a.f(t);};O365SuiteServiceProxy.a.i=function(n){return n.substr(0,8).toLowerCase()==="https://"||n.substr(0,7).toLowerCase()==="http://"};O365SuiteServiceProxy.a.e=function(n,t,i,r){if(r){if(O365SuiteServiceProxy.a.a(n)||typeof n!==i)throw O365SuiteServiceProxy.a.c(String.format("Invalid field or parameter {0}",t),-2001);}else if(!O365SuiteServiceProxy.a.a(n)&&typeof n!==i)throw O365SuiteServiceProxy.a.c(String.format("Invalid field or parameter {0}",t),-2001);};O365SuiteServiceProxy.a.c=function(n,t){var i=Error.create(n);i.errorCode=t;return i};O365SuiteServiceProxy.a.f=function(n){return O365SuiteServiceProxy.a.c(String.format("Invalid field or parameter {0}",n),-2001)};O365SuiteServiceProxy.a.g=function(n){return O365SuiteServiceProxy.m.b(n,!0,!0)};O365SuiteServiceProxy.ServiceHandlers=function(){};O365SuiteServiceProxy.ServiceHandlers.onBeforeSendRequestAdmin=function(n,t,i){var r=O365SuiteServiceProxy.m.a("s.AjaxSessionKey");r&&n.setRequestHeader("AjaxSessionKey",r);return null};O365SuiteServiceProxy.ServiceHandlers.onBeforeSendRequestSuiteService=function(n,t,i){var f="X-OWA-CANARY";var e="X-OWA-CANARY-DEBUG";var r=O365SuiteServiceProxy.m.a(f);var u=O365SuiteServiceProxy.m.a(e);r&&n.setRequestHeader(f,r);u&&n.setRequestHeader(e,u);return null};O365SuiteServiceProxy.ServiceHandlers.i=function(n,t){for(var r=new Array(t.length),i=0;i<t.length;i++)r[i]=t[i].host;return O365SuiteServiceProxy.ServiceHandlers.validateOrigin(O365SuiteServiceProxy.e.b(n),r)};O365SuiteServiceProxy.ServiceHandlers.validateOrigin=function(n,t){var f=253;if(!t||n.length>f)return!1;for(var u=!1,r,i=0;i<t.length;i++){if(O365SuiteServiceProxy.a.b(t[i]))return!1;r=new RegExp(t[i],"i");if(r.test(n)){u=!0;break}}return u};O365SuiteServiceProxy.ServiceHandlers.j=function(n,t){if(O365SuiteServiceProxy.a.b(n)||O365SuiteServiceProxy.a.a(t))return!1;for(var e=!1,i,o=O365SuiteServiceProxy.e.b(n),s=O365SuiteServiceProxy.e.d(n),u=0;u<t.length;u++){var r=t[u];i=new RegExp(r.host,"i");if(i.test(o)){if(O365SuiteServiceProxy.a.a(r.paths))return!1;for(var f=0;f<r.paths.length;f++){i=new RegExp(r.paths[f],"i");if(i.test(s)){e=!0;break}}break}}return e};O365SuiteServiceProxy.ServiceHandlers.d=function(n,t,i){if(O365SuiteServiceProxy.a.b(n)||O365SuiteServiceProxy.a.b(t)||O365SuiteServiceProxy.a.a(i))return!1;for(var e=!1,h=O365SuiteServiceProxy.e.b(n),c=O365SuiteServiceProxy.e.b(t),u=0;u<i.length;u++){var r=i[u];var s=O365SuiteServiceProxy.e.b(r.resource);if(s.toLowerCase()===h.toLowerCase()){if(O365SuiteServiceProxy.a.a(r.hosts))return!1;for(var f=0;f<r.hosts.length;f++){var o=O365SuiteServiceProxy.e.b(r.hosts[f]);if(o.toLowerCase()===c.toLowerCase()){e=!0;break}}break}}return e};O365SuiteServiceProxy.ServiceHandlers.IsAllowedApi=function(n){if(O365SuiteServiceProxy.a.b(n))return!1;var t=O365SuiteServiceProxy.e.d(n);if(t in O365SuiteServiceProxy.ServiceHandlers.a)if(O365SuiteServiceProxy.ServiceHandlers.a[t]){var i=O365SuiteServiceProxy.e.j(n).replace("&UA=0","");if(i in O365SuiteServiceProxy.ServiceHandlers.b)return!0}else return!0;else if(t.startsWith("O365SuiteService/api/"))return!0;return t==="owa/ev.owa2"||t==="ev.owa2"?O365SuiteServiceProxy.ServiceHandlers.e(n):!1};O365SuiteServiceProxy.ServiceHandlers.f=function(){var n={};n["action=GetReminders"]=!0;n["action=GetOwaUserConfiguration"]=!0;n["action=SetNotificationSettings"]=!0;n["action=FindItem"]=!0;n["action=GetUserAvailabilityInternal"]=!0;n["action=GetCalendarFolders"]=!0;n["action=ProcessSuiteStorage"]=!0;n["action=SubscribeToNotification"]=!0;n["action=GetReminders"]=!0;n["action=PerformReminderAction"]=!0;n["action=GetOwaUserOofSettings"]=!0;n["action=SetUserTheme"]=!0;n["action=SetUserLocale"]=!0;n["action=UnsubscribeToNotification"]=!0;n["action=GetDaysUntilPasswordExpiration"]=!0;n["action=GetModernGroups"]=!0;n["action=GetModernGroup"]=!0;n["action=GetModernGroupUnseenItems"]=!0;n["action=GetCalendarFolderConfiguration"]=!0;n["action=SubscribeToGroupUnseenNotification"]=!0;n["action=SubscribeToGroupNotification"]=!0;n["action=GetSocialActivityNotifications"]=!0;n["action=GetSocialActivityNotifications2"]=!0;n["action=MarkSocialActivityNotificationsAsSeen"]=!0;n["action=MarkSocialActivityNotificationsAsSeen2"]=!0;n["action=GetBingHelpSearchResults"]=!0;n["format=json"]=!0;n["action=TestAddReminders"]=!0;n["action=TestDeleteAllReminders"]=!0;n["action=TestAddItems"]=!0;n["action=TestDeleteAllItems"]=!0;n["action=TestAddCalendarFolders"]=!0;n["action=TestAddCalendarGroups"]=!0;n["action=TestDeleteAllCalendarFolders"]=!0;n["action=TestDeleteAllCalendarGroups"]=!0;n["action=TestAddUserAvailability"]=!0;n["action=TestDeleteAllUserAvailability"]=!0;n["action=TestAddOwaUserOofSettings"]=!0;n["action=TestDeleteNotifications"]=!0;n["action=TestAddNotifications"]=!0;n["action=TestGetSettings"]=!0;return n};O365SuiteServiceProxy.ServiceHandlers.h=function(){var n={};n.ecnsq=!0;n.brwnm=!0;n.cid=!0;n.syncFnshRq=!0;n.ns=!0;n.ev=!0;n.Fn=!0;n.UA=!0;n["UX-E4E-CANARY"]=!0;n["X-OWA-CANARY"]=!0;n["X-OWA-CANARY-DEBUG"]=!0;n["X-E4E-CANARY-DEBUG"]=!0;return n};O365SuiteServiceProxy.ServiceHandlers.g=function(){var n={};n["owa/service.svc"]=!0;n["SuiteService.svc/"]=!0;n["SuiteService.svc"]=!0;n["owa/ev.owa2"]=!0;n["ev.owa2"]=!0;n["Microsoft.Online.BOX.Admin.UI.SystemAlert.GetAlerts.model"]=!0;n["Microsoft.Online.BOX.Admin.UI.AppHub.AppUICallbacks.GetPrePinnedAppTiles.model"]=!0;n["Microsoft.Online.BOX.Admin.UI.AppHub.AppUICallbacks.GetAllAppTilesForAllCollectors.model"]=!0;n["api/myapps/GetAllApps"]=!1;n["api/myapps/GetAppDetails"]=!1;n["api/myapps/GetCompleteAppData"]=!1;n["api/myapps/ExecuteAppCustomAction"]=!1;n["api/myapps/ActivatePendingProvisioningApps"]=!1;n["owa/service.svc/s/GetPersonaPhoto"]=!1;n["api/settings/cards"]=!1;n["api/settings/cards/data"]=!1;n["api/settings/theme"]=!1;n["api/settings/language"]=!1;n["api/settings/startpage"]=!1;n["api/settings/contactPreferences"]=!1;n["api/NotificationsSettings/User"]=!1;n["api/settings/SPO/MySiteUrl"]=!1;n["api/settings/regiontimezone"]=!1;n["api/profile/photo"]=!1;return n};O365SuiteServiceProxy.ServiceHandlers.e=function(n){if(O365SuiteServiceProxy.a.b(n)||n===" ")return!1;var u=n.split("?");if(u.length===2){var i=u[1];if(O365SuiteServiceProxy.a.b(i)||i===" ")return!1;for(var f=i.split("&"),t=0;t<f.length;t++){var r=f[t].split("=");if(r.length===2){if(!(r[0]in O365SuiteServiceProxy.ServiceHandlers.c))return!1}else return!1}return!0}return!1};O365SuiteServiceProxy.SSRqD=function(){};O365SuiteServiceProxy.SSRqD.prototype={userId:null,clear:!1,reads:null,writes:null,deletes:null,requestType:0};O365SuiteServiceProxy.StS=function(){};O365SuiteServiceProxy.StS.a=function(n,t){if(n&&!n.startsWith(t+"//"))throw O365SuiteServiceProxy.a.c("Access denied",-2010);};O365SuiteServiceProxy.SSWE=function(){};O365SuiteServiceProxy.SSWE.prototype={key:null,value:null};O365SuiteServiceProxy.b=function(){};O365SuiteServiceProxy.b.b=function(n,t){t.val=0;var i=n.errorCode;if(i){t.val=i;return!0}else return!1};O365SuiteServiceProxy.b.a=function(n){var t;var r,i;return(i=O365SuiteServiceProxy.b.b(n,r={val:t}),t=r.val,i)&&(t===-1010||t===-1007)};O365SuiteServiceProxy.t=function(){};O365SuiteServiceProxy.t.a=function(n){var t=window.self;return t.MSA?new window.MSA.MeControl.UserStateModel(n):null};O365SuiteServiceProxy.g=function(){};O365SuiteServiceProxy.g.e=function(n,t){var r=new O365SuiteServiceProxy.u;var u=O365SuiteServiceProxy.m.a("SuiteServiceProxyKey");var e=null;var o=null;if(O365SuiteServiceProxy.a.b(u)){u=O365SuiteServiceProxy.m.a("ClientStorageCookie");if(O365SuiteServiceProxy.a.b(u))throw O365SuiteServiceProxy.a.c("Session storage error",-2007);else u=decodeURIComponent(u)}var f=u.split("&");if(f.length!==2)throw O365SuiteServiceProxy.a.c("Session storage error",-2007);e=f[0];o=f[1];if(O365SuiteServiceProxy.a.b(n.userId))throw O365SuiteServiceProxy.a.c("Session storage error",-2004);var i=window.sessionStorage;if(!i)throw O365SuiteServiceProxy.a.c("Session storage error",-2005);var s=window.MsrCryptoUtils;if(!s)throw O365SuiteServiceProxy.a.c("Session storage error",-2006);try{MsrCryptoUtils.ComputeSHA256(n.userId,function(u){var f=i.getItem("CurrentUserId");f&&u!==f&&i.clear();i.setItem("CurrentUserId",u);O365SuiteServiceProxy.g.g(n,r,i);O365SuiteServiceProxy.g.h(n,r,i);O365SuiteServiceProxy.g.i(n,e,o,i,r,t)},function(n){var i=n?n:"Session storage error";r.resetError=O365SuiteServiceProxy.a.c(i,-2008);t(r)},!0)}catch(h){r.resetError=h;t(r)}};O365SuiteServiceProxy.g.f=function(n,t){var r=window.localStorage;if(!r)throw O365SuiteServiceProxy.a.c("Session storage error",-2005);if(!O365SuiteServiceProxy.g.d){_o365su.a.a(window.self,"storage",function(){},!1);O365SuiteServiceProxy.g.d=!0}if(n.clear)throw O365SuiteServiceProxy.a.c("Invalid operation",-2010);var i=new O365SuiteServiceProxy.u;if(n.deletes)try{for(var s=0;s<n.deletes.length;s++){var h=n.deletes[s];O365SuiteServiceProxy.StS.a(h,"O365S");r.removeItem(h)}}catch(y){i.deleteError=y}if(n.writes)try{for(var v={},o=0;o<n.writes.length;o++){var u=n.writes[o];O365SuiteServiceProxy.StS.a(u.key,"O365S");r.setItem(u.key,u.value)}}catch(l){i.writeError=l}if(n.reads)try{for(var c={},f=0;f<n.reads.length;f++){var e=n.reads[f];O365SuiteServiceProxy.StS.a(e,"O365S");c[e]=r.getItem(e)}i.reads=c}catch(a){i.readError=a}t(i)};O365SuiteServiceProxy.g.g=function(n,t,i){try{n.clear&&i.clear()}catch(r){t.clearError=r}};O365SuiteServiceProxy.g.h=function(n,t,i){try{if(!1===O365SuiteServiceProxy.a.a(n.deletes))for(var r=0;r<n.deletes.length;r++){var u=n.deletes[r];i.removeItem(u)}}catch(f){t.deleteError=f}};O365SuiteServiceProxy.g.i=function(n,t,i,r,u,f){try{!1===O365SuiteServiceProxy.a.a(n.writes)?O365SuiteServiceProxy.g.c(t,i,n.writes,0,r,function(){O365SuiteServiceProxy.g.b(n,t,i,r,u,f)},function(e){u.writeError=e;O365SuiteServiceProxy.g.b(n,t,i,r,u,f)}):O365SuiteServiceProxy.g.b(n,t,i,r,u,f)}catch(e){u.writeError=e;O365SuiteServiceProxy.g.b(n,t,i,r,u,f)}};O365SuiteServiceProxy.g.b=function(n,t,i,r,u,f){var s={};try{if(!1===O365SuiteServiceProxy.a.a(n.reads)){var e={};O365SuiteServiceProxy.g.a(t,i,n.reads,0,e,r,function(n){u.reads=n;f(u)},function(n){u.readError=n;f(u)})}}catch(o){u.readError=o;f(u)}};O365SuiteServiceProxy.g.c=function(n,t,i,r,u,f,e){if(i&&r<i.length)if(n)MsrCryptoUtils.h(n,t,"$"+i[r].value+"$",function(o){u.setItem(i[r].key,o);O365SuiteServiceProxy.g.c(n,t,i,r+1,u,f,e)},function(n){var t=n?n:"Session storage error";e(O365SuiteServiceProxy.a.c(t,-2009))});else{u.setItem(i[r].key,i[r].value);O365SuiteServiceProxy.g.c(n,t,i,r+1,u,f,e)}else f()};O365SuiteServiceProxy.g.a=function(n,t,i,r,u,f,e,o){if(i&&r<i.length){var h=i[r];var s=f.getItem(h);if(s===null)O365SuiteServiceProxy.g.a(n,t,i,r+1,u,f,e,o);else if(n)MsrCryptoUtils.g(n,t,s,function(s){O365SuiteServiceProxy.a.a(s)||!1===s.startsWith("$")||!1===s.endsWith("$")||s.length<=2?f.clear():u[h]=s.substr(1,s.length-2);O365SuiteServiceProxy.g.a(n,t,i,r+1,u,f,e,o)},function(n){o(Error.create(n))});else{u[h]=s;O365SuiteServiceProxy.g.a(n,t,i,r+1,u,f,e,o)}}else e(u)};O365SuiteServiceProxy.u=function(){};O365SuiteServiceProxy.u.prototype={reads:null,resetError:null,clearError:null,deleteError:null,writeError:null,readError:null};O365SuiteServiceProxy.c=function(){};O365SuiteServiceProxy.c.a=function(){return _o365su.c.b("performance.now")?performance.now():Date.now()};O365SuiteServiceProxy.c.c=function(n){return O365SuiteServiceProxy.c.e(O365SuiteServiceProxy.c.b(n,"resource"))};O365SuiteServiceProxy.c.b=function(n,t){return _o365su.c.b("performance.getEntriesByName")?performance.getEntriesByName(n,t):null};O365SuiteServiceProxy.c.d=function(n){var t={};t.fetchStart=n.fetchStart;t.requestStart=n.requestStart;t.responseStart=n.responseStart;t.responseEnd=n.responseEnd;return JSON.stringify(t)};O365SuiteServiceProxy.c.e=function(n){if(n){for(var f=[],u=n,e=u.length,r=0;r<e;++r){var i=u[r];var t={};t.connectEnd=i.connectEnd;t.connectStart=i.connectStart;t.decodedBodySize=i.decodedBodySize;t.domainLookupEnd=i.domainLookupEnd;t.domainLookupStart=i.domainLookupStart;t.duration=i.duration;t.encodedBodySize=i.encodedBodySize;t.entryType=i.entryType;t.fetchStart=i.fetchStart;t.initiatorType=i.initiatorType;t.name=i.name;t.nextHopProtocol=i.nextHopProtocol;t.redirectEnd=i.redirectEnd;t.redirectStart=i.redirectStart;t.requestStart=i.requestStart;t.responseEnd=i.responseEnd;t.responseStart=i.responseStart;t.secureConnectionStart=i.secureConnectionStart;t.startTime=i.startTime;t.transferSize=i.transferSize;t.workerStart=i.workerStart;Array.add(f,t)}return f}else return null};MsrCryptoUtils.registerClass("MsrCryptoUtils");O365SuiteServiceProxy.z.registerClass("O365SuiteServiceProxy.z");O365SuiteServiceProxy.k.registerClass("O365SuiteServiceProxy.k");O365SuiteServiceProxy.JQueryAPIImplementor.registerClass("O365SuiteServiceProxy.JQueryAPIImplementor");O365SuiteServiceProxy.ServiceHandlers.registerClass("O365SuiteServiceProxy.ServiceHandlers");O365SuiteServiceProxy.SSRqD.registerClass("O365SuiteServiceProxy.SSRqD");O365SuiteServiceProxy.SSWE.registerClass("O365SuiteServiceProxy.SSWE");O365SuiteServiceProxy.u.registerClass("O365SuiteServiceProxy.u");O365SuiteServiceProxy.p.MSA="msa";O365SuiteServiceProxy.p.AAD="aad";O365SuiteServiceProxy.p.msaFed="msaFed";O365SuiteServiceProxy.JQueryAdapter.$$cctor();O365SuiteServiceProxy.JQueryAPIImplementor.b=new RegExp("^<(\\w+)(.*)>");O365SuiteServiceProxy.e.e=0;O365SuiteServiceProxy.e.c="SP.RequestExecutor";O365SuiteServiceProxy.ServiceHandlers.c=O365SuiteServiceProxy.ServiceHandlers.h();O365SuiteServiceProxy.ServiceHandlers.b=O365SuiteServiceProxy.ServiceHandlers.f();O365SuiteServiceProxy.ServiceHandlers.a=O365SuiteServiceProxy.ServiceHandlers.g();O365SuiteServiceProxy.StS.OSS="O365S";O365SuiteServiceProxy.StS.DSPS="//";O365SuiteServiceProxy.g.d=!1;/*! Version=16.00.2403.000 */
Type.registerNamespace("O365SuiteServiceProxy");O365SuiteServiceProxy.H=function(){};O365SuiteServiceProxy.A=function(){};O365SuiteServiceProxy.A.prototype={a:null,b:0};O365SuiteServiceProxy.RequestExecutorMessageProcessor=function(n,t){this.c=n;this.a=t;this.a.method=O365SuiteServiceProxy.a.b(this.a.method)?"GET":this.a.method.toUpperCase();this.d=0};O365SuiteServiceProxy.RequestExecutorMessageProcessor.k=function(n){O365SuiteServiceProxy.RequestExecutorMessageProcessor.d||(O365SuiteServiceProxy.RequestExecutorMessageProcessor.d={});n=O365SuiteServiceProxy.RequestExecutorMessageProcessor.g(n);var t=O365SuiteServiceProxy.RequestExecutorMessageProcessor.d[n];if(!t)return null;var i=new Date;return t.b<i.getTime()?null:t.a};O365SuiteServiceProxy.RequestExecutorMessageProcessor.g=function(n){var t;t=n.indexOf("?");t>0&&(n=n.substr(0,t));t=n.indexOf("#");t>0&&(n=n.substr(0,t));n=n.toLowerCase();t=n.indexOf("/_layouts");t>0&&(n=n.substr(0,t));t=n.indexOf("/_vti_");t>0&&(n=n.substr(0,t));t=n.indexOf("/_api");t>0&&(n=n.substr(0,t));n.charAt(n.length-1)!=="/"&&(n=n+"/");n+="_api/contextinfo";return n};O365SuiteServiceProxy.RequestExecutorMessageProcessor.setTrustedOriginAuthorities=function(n){O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthorities=n;O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthoritiesSetFromServer=!0};O365SuiteServiceProxy.RequestExecutorMessageProcessor.getTrustedOriginAuthoritiesSetFromServer=function(){return O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthoritiesSetFromServer};O365SuiteServiceProxy.RequestExecutorMessageProcessor.init=function(n){O365SuiteServiceProxy.RequestExecutorMessageProcessor.a=n;if(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a){O365SuiteServiceProxy.a.d(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.formDigestHandlingEnabled)&&(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.formDigestHandlingEnabled=!1);O365SuiteServiceProxy.a.d(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.initErrorCode)&&(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.initErrorCode=0);O365SuiteServiceProxy.a.d(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.initErrorMessage)&&(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.initErrorMessage="");O365SuiteServiceProxy.a.d(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.isUnAuth)&&(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.isUnAuth=!1);O365SuiteServiceProxy.a.d(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.shouldAttachOauthTokens)&&(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.shouldAttachOauthTokens=!1)}if(!O365SuiteServiceProxy.RequestExecutorMessageProcessor.f){var t=window.O365SuiteServiceProxy.RequestExecutorMessageProcessor.internalOnMessage;if(window.addEventListener){window.addEventListener("message",t,!1);O365SuiteServiceProxy.RequestExecutorMessageProcessor.f=!0}else if(window.attachEvent){window.attachEvent("onmessage",t);O365SuiteServiceProxy.RequestExecutorMessageProcessor.f=!0}}};O365SuiteServiceProxy.RequestExecutorMessageProcessor.internalOnMessage=function(n){if(!O365SuiteServiceProxy.a.a(n)){var r=O365SuiteServiceProxy.RequestExecutorMessageProcessor.a;if(r){var k=n.data;var i=n.origin;if(!O365SuiteServiceProxy.a.b(i)&&!O365SuiteServiceProxy.a.b(k)){var t=O365SuiteServiceProxy.a.j(k);if(!O365SuiteServiceProxy.a.a(t)&&!O365SuiteServiceProxy.a.b(t.postMessageId)&&t.postMessageId.substr(0,O365SuiteServiceProxy.e.c.length)===O365SuiteServiceProxy.e.c&&!O365SuiteServiceProxy.a.b(t.command)){var e=null;if(!O365SuiteServiceProxy.a.b(t.url)){e=O365SuiteServiceProxy.e.a(t.url).toLowerCase();if(!e.startsWith("https://"))return;if(e!==O365SuiteServiceProxy.RequestExecutorMessageProcessor.h&&!O365SuiteServiceProxy.ServiceHandlers.i(e,O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.allowedEndpoints))return}if(t.command==="Ping"){if(O365SuiteServiceProxy.a.a(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthoritiesSetFromServer)||O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthoritiesSetFromServer)O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,0,"",i);else{var g=0;var s=0;s=window.setInterval(function(){if(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.trustedOriginAuthoritiesSetFromServer||g>O365SuiteServiceProxy.RequestExecutorMessageProcessor.j){if(s){window.clearInterval(s);s=0}O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,0,"",i);return}g++},O365SuiteServiceProxy.RequestExecutorMessageProcessor.i)}return}if((!r.trustedOriginAuthorities||!r.trustedOriginAuthorities.length)&&!r.originAuthorityValidator){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1006,"No trusted origins",i);return}var o=!1;var c=O365SuiteServiceProxy.e.b(i).toLowerCase();if(r.trustedOriginAuthorities)for(var h=0;h<r.trustedOriginAuthorities.length;h++){var nt=r.trustedOriginAuthorities[h].toLowerCase();if(nt===c){o=!0;break}}!o&&r.originAuthorityValidator&&(o=r.originAuthorityValidator(c,r.trustedOriginAuthorities));if(!o){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1005,c,i);return}if(t.command==="Storage")try{var u=t.requestObject;var d=function(n){var r=new O365SuiteServiceProxy.k;r.command="Storage";r.errorCode=0;r.errorMessage=null;r.postMessageId=t.postMessageId;r.responseAvailable=!0;r.responseObject=n;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(r,i)};if(u.requestType===1){if(r.isUnAuth&&(u.clear||u.deletes&&u.deletes.length>0||u.writes&&u.writes.length>0))throw O365SuiteServiceProxy.a.c("Access denied",-2010);O365SuiteServiceProxy.g.f(u,d)}else O365SuiteServiceProxy.g.e(u,d);return}catch(rt){var f=new O365SuiteServiceProxy.k;f.command="Storage";f.postMessageId=t.postMessageId;var b=rt.errorCode;if(b){f.errorCode=b;f.errorMessage=rt.message}else{f.errorCode=-1008;f.errorMessage="Session storage error"}O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(f,i)}if(t.command==="PendingGet"){if(!O365SuiteServiceProxy.RequestExecutorMessageProcessor.e){var it=new O365SuiteServiceProxy.RequestExecutorPendingGetMessageProcessor(i);O365SuiteServiceProxy.RequestExecutorMessageProcessor.e=it}O365SuiteServiceProxy.RequestExecutorMessageProcessor.e.a(t)}if(t.command==="Query"){if(O365SuiteServiceProxy.a.b(t.url)||O365SuiteServiceProxy.a.b(t.method))return;if(r.initErrorCode<0){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,r.initErrorCode,r.initErrorMessage,i);return}if(r.shouldAttachOauthTokens){var l=e;if(!O365SuiteServiceProxy.a.b(t.resource)){if(!O365SuiteServiceProxy.ServiceHandlers.d(t.resource,t.url,O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.allowedResources)){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1015,"This resource cannot be used for this endpoint.",i);return}l=t.resource}var tt=function(n,r){if(!O365SuiteServiceProxy.a.a(n)&&n.length>0){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1014,n,i);return}else{t.headers||(t.headers={});t.headers.Authorization="Bearer "+r;var u=new O365SuiteServiceProxy.RequestExecutorMessageProcessor(i,t);u.g()}};O365OAuth.a.b(l,tt)}else{var a=new O365SuiteServiceProxy.RequestExecutorMessageProcessor(i,t);var v=0;v>0?window.setTimeout(function(){a.g()},v):a.g()}}if(t.command==="TokenPrefetch"){if(!r.shouldAttachOauthTokens){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1013,"Iframe not configured for OAuth requests.",e);return}var w=e;if(!O365SuiteServiceProxy.a.b(t.resource)){if(!O365SuiteServiceProxy.ServiceHandlers.d(t.resource,t.url,O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.allowedResources)){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1015,"This resource cannot be used for this endpoint.",i);return}w=t.resource}O365OAuth.a.b(w,function(n,r){if(!O365SuiteServiceProxy.a.a(n)&&n.length>0){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,-1014,n,i);return}else O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(t,0,"",i)})}if(t.command==="UserState"){var p=t.requestObject;if(O365SuiteServiceProxy.a.a(p))return;var y=O365SuiteServiceProxy.t.a(p);y&&y.getUserState(function(n){var r=new O365SuiteServiceProxy.k;r.command="UserState";r.errorCode=0;r.errorMessage=null;r.postMessageId=t.postMessageId;r.responseAvailable=!0;r.responseObject=n;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(r,i)},function(){var n=new O365SuiteServiceProxy.k;n.command="UserState";n.errorCode=-1012;n.errorMessage=null;n.postMessageId=t.postMessageId;n.responseAvailable=!1;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(n,i)},t.timeout)}}}}}};O365SuiteServiceProxy.RequestExecutorMessageProcessor.b=function(n,t,i,r){var u=new O365SuiteServiceProxy.k;u.command=n.command;u.postMessageId=n.postMessageId;u.responseAvailable=!1;u.errorCode=t;u.errorMessage=i;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(u,r)};O365SuiteServiceProxy.RequestExecutorMessageProcessor.c=function(n,t){var i=JSON.stringify(n);window.parent.postMessage(i,t)};O365SuiteServiceProxy.RequestExecutorMessageProcessor.prototype={c:null,a:null,d:0,b:null,g:function(){if(this.a.method!=="GET"&&O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.formDigestHandlingEnabled){var n=O365SuiteServiceProxy.RequestExecutorMessageProcessor.k(this.a.url);O365SuiteServiceProxy.a.b(n)?this.h():this.f(n)}else this.f(null)},h:function(){var i=O365SuiteServiceProxy.RequestExecutorMessageProcessor.g(this.a.url);i=O365SuiteServiceProxy.a.g(i);var n=O365SuiteServiceProxy.a.h();n.open("POST",i);n.setRequestHeader("ACCEPT","application/json;odata=verbose");if(this.a.timeout>0){var r=this;this.d=window.setTimeout(function(){n.onreadystatechange=null;n.abort();var t=new O365SuiteServiceProxy.k;t.command="Query";t.errorCode=-1001;t.errorMessage="Request was aborted or timed out";t.postMessageId=r.a.postMessageId;t.responseAvailable=!1;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(t,r.c)},this.a.timeout)}var t=this;n.onreadystatechange=function(){if(n&&n.readyState===4){if(t.d){window.clearTimeout(t.d);t.d=0}n.onreadystatechange=null;t.i(n)}};n.send("")},i:function(n){if(n.status!==200){var f=this.e(n);f.errorCode=-1003;f.errorMessage=String.format("Status:{0}, Content-type:{1}",n.status.toString(),n.getResponseHeader("content-type"));O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(f,this.c);return}var o=n.getResponseHeader("content-type");if(O365SuiteServiceProxy.a.b(o)||o.toLowerCase().indexOf("json")<0){var e=this.e(n);e.errorCode=-1002;e.errorMessage="Wrong content-type";O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(e,this.c);return}var u=JSON.parse(n.responseText);if(O365SuiteServiceProxy.a.a(u)){var i=this.e(n);i.errorCode=-1002;i.errorMessage="Unable to parse json";O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(i,this.c);return}var t=new O365SuiteServiceProxy.A;try{t.a=u.d.GetContextWebInformation.FormDigestValue;var h=u.d.GetContextWebInformation.FormDigestTimeoutSeconds;t.b=+new Date+h*750}catch(c){var r=this.e(n);r.errorCode=-1002;r.errorMessage="Unexpected Digest Info format";O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(r,this.c);return}O365SuiteServiceProxy.RequestExecutorMessageProcessor.d||(O365SuiteServiceProxy.RequestExecutorMessageProcessor.d={});var s=O365SuiteServiceProxy.RequestExecutorMessageProcessor.g(this.a.url);O365SuiteServiceProxy.RequestExecutorMessageProcessor.d[s]=t;this.f(t.a)},e:function(n){var t=new O365SuiteServiceProxy.k;t.command="Query";t.errorCode=0;t.errorMessage=null;t.postMessageId=this.a.postMessageId;t.responseAvailable=!0;t.statusText=n.statusText;t.statusCode=n.status;t.contentType=n.getResponseHeader("content-type");t.allResponseHeaders=n.getAllResponseHeaders();t.responseText=n.responseText;t.readyState=n.readyState;return t},f:function(n){var r;r=O365SuiteServiceProxy.a.a(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.allowedEndpoints)?O365SuiteServiceProxy.ServiceHandlers.IsAllowedApi(this.a.url):O365SuiteServiceProxy.ServiceHandlers.j(this.a.url,O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.allowedEndpoints);if(!r){O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(this.a,-1009,"Access denied",this.c);return}this.b=O365SuiteServiceProxy.a.h();var u=this.a.url;u=O365SuiteServiceProxy.a.g(u);this.b.open(this.a.method,u);var o=!1;if(this.a.headers){var s=this.a.headers;for(var h in s){var t={key:h,value:s[h]};t.key.toLowerCase()==="x-requestdigest"&&(o=!0);this.b.setRequestHeader(t.key,t.value)}}o||O365SuiteServiceProxy.a.b(n)||this.b.setRequestHeader("X-RequestDigest",n);O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.shouldAttachOauthTokens||this.b.setRequestHeader("X-SuiteServiceProxyOrigin",this.c);this.a.binaryStringResponseBody&&O365SuiteServiceProxy.e.i(this.b);if(this.a.timeout>0){var c=this;this.d=window.setTimeout(function(){c.l()},this.a.timeout)}var l=this;this.b.onreadystatechange=function(){l.k()};var i;i=this.a.binaryStringRequestBody?O365SuiteServiceProxy.e.g(this.a.body):this.a.body;var e=!1;if(O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.onBeforeSendRequest){var f=O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.onBeforeSendRequest(this.b,this.a,O365SuiteServiceProxy.RequestExecutorMessageProcessor.a.context);if(f){O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(f,this.c);e=!0}}e||this.b.send(i)},l:function(){if(this.b){this.b.onreadystatechange=null;this.b.abort();var n=new O365SuiteServiceProxy.k;n.command="Query";n.errorCode=-1001;n.errorMessage="Request was aborted or timed out";n.postMessageId=this.a.postMessageId;n.responseAvailable=!1;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(n,this.c)}},k:function(){if(this.b&&(this.b.readyState===4||this.b.readyState===3)){var n=new O365SuiteServiceProxy.k;if(this.b.readyState===4){if(this.d){window.clearTimeout(this.d);this.d=0}this.b.onreadystatechange=null;this.a.getPerformanceTrace&&(n.performanceTrace=this.j(this.a.url))}n.command="Query";n.errorCode=0;n.errorMessage=null;n.postMessageId=this.a.postMessageId;n.responseAvailable=!0;n.statusText=this.b.statusText;n.statusCode=this.b.status;n.contentType=this.b.getResponseHeader("content-type");n.allResponseHeaders=this.b.getAllResponseHeaders();n.readyState=this.b.readyState;n.binaryStringResponseBody=this.a.binaryStringResponseBody;n.responseText=this.a.binaryStringResponseBody?O365SuiteServiceProxy.e.f(this.b.response):this.b.responseText;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(n,this.c)}},j:function(n){var t=O365SuiteServiceProxy.c.c(n);return t&&t.length>0?t[0]:null}};O365SuiteServiceProxy.H.registerClass("O365SuiteServiceProxy.H");O365SuiteServiceProxy.A.registerClass("O365SuiteServiceProxy.A");O365SuiteServiceProxy.RequestExecutorMessageProcessor.registerClass("O365SuiteServiceProxy.RequestExecutorMessageProcessor");O365SuiteServiceProxy.RequestExecutorMessageProcessor.d=null;O365SuiteServiceProxy.RequestExecutorMessageProcessor.a=null;O365SuiteServiceProxy.RequestExecutorMessageProcessor.f=!1;O365SuiteServiceProxy.RequestExecutorMessageProcessor.h=O365SuiteServiceProxy.e.a(window.location.href).toLowerCase();O365SuiteServiceProxy.RequestExecutorMessageProcessor.e=null;O365SuiteServiceProxy.RequestExecutorMessageProcessor.i=400;O365SuiteServiceProxy.RequestExecutorMessageProcessor.j=10;/*! Version=16.00.2403.000 */
Type.registerNamespace("O365SuiteServiceProxy");O365SuiteServiceProxy.PendingGetMechanism=function(){};O365SuiteServiceProxy.PendingGetMechanism.prototype={Xhr:1,iFrame:2};O365SuiteServiceProxy.PendingGetMechanism.registerEnum("O365SuiteServiceProxy.PendingGetMechanism",!1);O365SuiteServiceProxy.PendingGetRequestType=function(){};O365SuiteServiceProxy.PendingGetRequestType.prototype={Initialize:1,Start:2,Stop:3,Detach:4,Abort:5};O365SuiteServiceProxy.PendingGetRequestType.registerEnum("O365SuiteServiceProxy.PendingGetRequestType",!1);O365SuiteServiceProxy.G=function(){};O365SuiteServiceProxy.G.prototype={b:null,d:null,e:function(n){switch(n.RequestType){case 1:if(!n.NotificationCallback)throw Error.argumentNull("NotificationDelegate");this.d=n.NotificationCallback;this.g();break;case 2:this.h(n.Url);break;case 3:this.i();break;case 4:this.c();break;case 5:this.f();break;default:throw Error.argumentOutOfRange("request.RequestType");}}};O365SuiteServiceProxy.y=function(n){O365SuiteServiceProxy.y.initializeBase(this);this.b=n};O365SuiteServiceProxy.y.prototype={a:null,g:function(){},h:function(n){var i=O365SuiteServiceProxy.m.b(this.b,!1,!1);n=n+"&X-SuiteServiceProxyOrigin="+i;this.a=new XMLHttpRequest;var r=this.a;var t=this;this.a.onreadystatechange=function(){t.a===r&&t.j()};this.a.open("GET",n,!0);O365SuiteServiceProxy.ServiceHandlers.onBeforeSendRequestSuiteService(this.a,null,null);this.a.setRequestHeader("X-SuiteServiceProxyOrigin",this.b);this.a.send(null)},i:function(){},f:function(){this.a&&this.a.abort()},c:function(){if(this.a){this.a.onreadystatechange=null;this.a=null}},j:function(){this.a&&(this.a.readyState===3?this.d(this.a.responseText):this.a.readyState===4&&this.c())}};O365SuiteServiceProxy.j=function(n){O365SuiteServiceProxy.j.initializeBase(this);this.b=n};O365SuiteServiceProxy.j.prototype={g:function(){if(O365SuiteServiceProxy.a.a(O365SuiteServiceProxy.j.a)){var n=window.document.createElement("iframe");n.id="hdnIfrm";n.setAttribute("frameborder","0");n.setAttribute("height","0");n.setAttribute("width","100%");document.body.appendChild(n);O365SuiteServiceProxy.j.a=document.getElementById("hdnIfrm");O365SuiteServiceProxy.j.a.src="about:blank";window.self.pR=this.d}},h:function(n){var t=O365SuiteServiceProxy.m.a("X-OWA-CANARY");if(t){var r=O365SuiteServiceProxy.m.b(this.b,!1,!1);var i=String.format("{0}&X-OWA-CANARY={1}&X-SuiteServiceProxyOrigin={2}",n,t,r);O365SuiteServiceProxy.a.a(O365SuiteServiceProxy.j.a)||O365SuiteServiceProxy.j.a.contentWindow.location.replace(i)}},i:function(){O365SuiteServiceProxy.a.a(O365SuiteServiceProxy.j.a)||O365SuiteServiceProxy.j.a.contentWindow.location.replace("about:blank")},c:function(){if(O365SuiteServiceProxy.j.a){document.body.removeChild(O365SuiteServiceProxy.j.a);O365SuiteServiceProxy.j.a.contentWindow.location.replace("about:blank");O365SuiteServiceProxy.j.a=null}window.self.pR=null},f:function(){}};O365SuiteServiceProxy.q=function(n,t){this.RequestType=n;this.Url=t};O365SuiteServiceProxy.q.prototype={RequestType:0,Url:null,PendingGetMechanism:0,NotificationCallback:null};O365SuiteServiceProxy.RequestExecutorPendingGetMessageProcessor=function(n){this.b=n};O365SuiteServiceProxy.RequestExecutorPendingGetMessageProcessor.prototype={d:null,c:null,b:null,a:function(n){if(n.command==="PendingGet"){var t=n.requestObject;try{switch(t.RequestType){case 1:if(O365SuiteServiceProxy.a.a(this.c))switch(t.PendingGetMechanism){case 1:this.c=new O365SuiteServiceProxy.y(this.b);break;case 2:this.c=new O365SuiteServiceProxy.j(this.b);break;default:throw Error.argument("PendingGetRequestData.PendingGetMechanism has unsupported value = "+t.RequestType);}var r=this;t.NotificationCallback=function(t){var i=new O365SuiteServiceProxy.k;i.command="Notification";i.postMessageId=n.postMessageId;i.responseAvailable=!0;i.responseObject=t;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(i,r.b)};this.d=n;this.c.e(t);break;case 2:if(O365SuiteServiceProxy.a.i(t.Url))throw Error.create("IFrame URL must be relative");this.c.e(t);O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(n,0,null,this.b);break;case 3:case 5:if(this.d){this.c.e(t);O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(n,0,null,this.b)}break;case 4:if(this.d){this.c.e(t);O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(this.d,0,null,this.b)}O365SuiteServiceProxy.RequestExecutorMessageProcessor.b(n,0,null,this.b);break;default:throw Error.argumentOutOfRange("request.RequestType");}}catch(u){if(this.d){var i=new O365SuiteServiceProxy.k;i.command="PendingGet";i.errorMessage=u.message;i.postMessageId=n.postMessageId;O365SuiteServiceProxy.RequestExecutorMessageProcessor.c(i,this.b)}}}}};O365SuiteServiceProxy.G.registerClass("O365SuiteServiceProxy.G");O365SuiteServiceProxy.y.registerClass("O365SuiteServiceProxy.y",O365SuiteServiceProxy.G);O365SuiteServiceProxy.j.registerClass("O365SuiteServiceProxy.j",O365SuiteServiceProxy.G);O365SuiteServiceProxy.q.registerClass("O365SuiteServiceProxy.q");O365SuiteServiceProxy.RequestExecutorPendingGetMessageProcessor.registerClass("O365SuiteServiceProxy.RequestExecutorPendingGetMessageProcessor");O365SuiteServiceProxy.j.a=null;/// Copyright (C) Microsoft Corporation. All rights reserved.

(function ()
{
    var w = window;
    w.MSA = {};
    var ME = w.MSA.MeControl = {};
    var storage = w.sessionStorage;

    var c_sessionStorageIdKey = 'msameid';
    var c_type = 'type';
    ME.IDP =
    {
        MSA: 'msa',
        AAD: 'aad'
    };
    
    ME.Log = new Logger();
    /* @constructor */function Logger()
    {
        /// <param name="onEventLog" type="String, * -> void">An event handler to capture QoS and Bici data</param>

        var _this = this;
        var _id;
        var _onEventLog;

        if (storage)
        {
            _id = storage.getItem(c_sessionStorageIdKey) || guid();
            try 
            {
                storage.setItem(c_sessionStorageIdKey, _id);
            }
            catch (e) { 
                // Safari private browsing will throw an exception
            }
        }
        else
        {
            _id = guid();
        }

        if (!Date.now)
        {
            Date.now = function()
            {
                return (new Date()).getTime();
            };
        }

        _this.setLogEvent = function (onEventLog)
        {
            /// <summary>Sets the event hander for logging</summary>
            /// <param name="onEventLog" type="String, * -> void">The event handler callback</param>
            
            _onEventLog = onEventLog;
        };

        _this.id = _id;

        _this.logQos = function (eventId, success, duration, errorCode, dataPoints)
        {
            /// <summary>Logs a QoS event</summary>
            /// <param name="eventId" type="String">An id for the event</param>
            /// <param name="success" type="Boolean">True if succeeded, false otherwise</param>
            /// <param name="duration" type="Number">The duration of the operation, in ms</param>
            /// <param name="errorCode" type="String" optional="true">An error code in case of failure</param>
            /// <param name="dataPoints" type="*" optional="true">A bag of extra information to be logged</param>

            dataPoints = dataPoints || {};
            dataPoints[c_type] = 'qos';
            dataPoints['success'] = success ? '1' : '0';
            dataPoints['duration'] = duration || 0;
            dataPoints['errorCode'] = errorCode || '';

            _this.logEvent(eventId, dataPoints);
        };

        _this.logEvent = function (eventId, dataPoints)
        {
            dataPoints = dataPoints || {};
            if (!dataPoints[c_type])
            {
                dataPoints[c_type] = 'bici';
            }
            
            dataPoints['ts'] = Date.now();
            dataPoints['uaid'] = _id;

            _onEventLog && _onEventLog(eventId, dataPoints);
        };

        function guid()
        {
            /// <summary>Generate a new random GUID compliant with RFC4122 version 4</summary>
            /// <returns type="String">The new GUID</returns>

            // Stitch in '4' in the third group to comply with RFC4122 version 4
            return (term4() + term4() + '-' + term4() + '-4' + term4().substr(0, 3) + '-' + term4() + '-' + term4() + term4() + term4()).toLowerCase();

            function term4()
            {
                return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
            }
        }
    }
})();

/// Copyright (C) Microsoft Corporation. All rights reserved.

(function (jQuery)
{
    var w = window;
    var ME = w.MSA.MeControl;

    // Regex that finds {#} so it can be replaced by the arguments in string format
    var c_FormatRegEx = /\{\d+\}/g;
    // Regex that finds { and } so they can be removed on a lookup for string format
    var c_FormatArgsRegEx = /[\{\}]/g;
    //encode if a character not matches with [a-zA-Z0-9_{space}.,-].
    var c_EncodeHtmlRegEx = /[^\w .,-]/g;

    ME.Strings = new StringUtils();
    /* @constructor */function StringUtils()
    {
        /// <summary>
        /// Defines the StringUtils class.
        /// </summary>

        var _this = this;
        var _disposed = false;
        var _strings = {};

        _this.addStrings = function(newStrings)
        {
            /// <summary>
            /// Adds new string resources
            /// </summary>
            /// <param name="newStrings" type="*">The new strings to be added</param>

            jQuery.extend(_strings, newStrings);
        };

        _this.getString = function(stringId, encode)
        {
            /// <summary>
            /// Gets a string resource
            /// </summary>
            /// <param name="stringId" type="String">The string value for the given string id</param>
            /// <param name="encode" type="Boolean" optional="true">If true, result will be HTML encoded</param>
            /// <returns type="String">The string resource</returns>

            var result = _strings[stringId] || _this.format('ERROR: {0}', stringId);

            return encode ? _this.encodeHtml(result) : result;
        };

        _this.startsWith = function(str, prefix)
        {
            /// <summary>
            /// Checks if the string starts with the provided prefix
            /// Usage: Strings.startsWith('abc', 'ab') returns true
            /// </summary>
            /// <param name="str" type="String">String to check</param>
            /// <param name="prefix" type="String">Prefix to match</param>
            /// <returns type="Boolean">Bool if the prefix is at the start of the string</returns>

            return (str.substr(0, prefix.length) === prefix);
        };

        _this.format = function (str, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10)
        {
            /// <summary>
            /// String Format is like C# string format.
            /// Usage Example: "hello {0}!".format("mike") will return "hello mike!"
            /// Calling format on a string with less arguments than specified in the format is invalid
            /// Example "I love {0} every {1}".format("CXP") will result in a Debug Exception.
            /// </summary>
            /// <param name="str" type="String">The string format</param>
            /// <param name="s1" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s2" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s3" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s4" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s5" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s6" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s7" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s8" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s9" type="String" optional="true">The values passed will be used in the string format</param>
            /// <param name="s10" type="String" optional="true">The values passed will be used in the string format</param>

            var args = arguments;

            //Callback match function
            function replace_func(match)
            {
                /// <param name="match" type="String">regex match</param>

                //looks up in the args
                var replacement = args[parseInt(match.replace(c_FormatArgsRegEx, "")) + 1];
                if (replacement == null)
                {
                    replacement = '';
                }
                
                return replacement;
            }

            return (str.replace(c_FormatRegEx, replace_func));
        };
        
        _this.dispose = function ()
        {
            /// <summary>
            /// Disposes the control
            /// </summary>

            if (!_disposed)
            {
                _strings = null;
                _disposed = true;
            }
        };

        _this.encodeHtml = function (str)
        {
            /// <summary>
            /// Aggressively encodes a string to be displayed in the browser. All non-letter characters are converted
            /// to their Unicode entity ref, e.g. &#65;, space, comma, and dash are left un-encoded as well.
            /// Usage: _divElement.innerHTML =_someValue.encodeHtml());
            /// </summary>
            /// <param name="str" type="String">The string to be encoded</param>
            /// <returns type="String">Html Encoded string</returns>

            if (!str)
            {
                return '';
            }

            var /* @dynamic */charCodeResult = {
                c: 0, // Code
                s: -1 // Next skip index
            };

            return str.replace(c_EncodeHtmlRegEx, function (match, ind, s)
            {
                /// <summary>
                /// Replace Helper Function
                /// </summary>
                /// <param name="_match" type="String">Regex Match</param>
                /// <param name="ind" type="Number">Index into the string where the match occurred</param>
                /// <param name="s" type="String">The string where the match occurred</param>
                /// <returns type="String">replaced match</returns>

                if (extendedCharCodeAt(s, ind, charCodeResult))
                {
                    return ['&#', charCodeResult.c, ';'].join('');
                }
                
                //If extendedCharCodeAt returns false that means this index is the low surrogate,
                //which has already been processed, so we remove it by returning an empty string.
                return '';
            });
        };

        
        function extendedCharCodeAt(str, idx, /* @dynamic */result)
        {
            /// <summary>
            /// Gets the char code from str at idx.
            /// Supports Secondary-Multilingual-Plane Unicode characters (SMP), e.g. codes above 0x10000
            /// </summary>
            /// <param name="str" type="String">String to get char code from</param>
            /// <param name="idx" type="Number">Index of char to get code for</param>
            /// <param name="result" type="*">Receives result code c: and index skip s: info</param>
            /// <returns>True if this method processed the char code</returns>

            var skip = (result.s === idx);
            if (!skip)
            {
                idx = idx || 0;
                var code = str.charCodeAt(idx);
                var hi, low;
                result.s = -1;
                if (code < 0xD800 || code > 0xDFFF)
                {
                    //Main case, Basic-Multilingual-Plane (BMP) code points.
                    result.c = code;
                }
                else if (code <= 0xDBFF) // High surrogate of SMP
                {
                    hi = code;
                    low = str.charCodeAt(idx + 1);
                    result.c = ((hi - 0xD800) * 0x400) + (low - 0xDC00) + 0x10000;
                    result.s = idx + 1;
                }
                else // Low surrogate of SMP, 0xDC00 <= code && code <= 0xDFFF
                {
                    //Shouldn't really ever come in here, previous call to this method would set skip index in result
                    //in high surrogate case, which is short-circuited at the start of this function.
                    result.c = -1;
                    skip = true;
                }
            }
            return !skip;
        }
    }
})(window.MejQuery);
/// Copyright (C) Microsoft Corporation. All rights reserved.

(function()
{
    var w = window;
    var ME = w.MSA.MeControl;
    var $str = ME.Strings;

    ME.Util =
    {
        appendQueryParameter: function (url, paramName, paramValue)
        {
            /// <summary>Appends a query string parameter and value to a given url</summary>
            /// <param name="url" type="String">The url to append the parameter to</param>
            /// <param name="paramName" type="String">The parameter name</param>
            /// <param name="paramValue" type="String">The parameter value</param>
            /// <returns type="String">The URl with the parameter</returns>

            if (!url)
            {
                return '';
            }

            return $str.format('{0}{1}{2}={3}', url, url.indexOf('?') === -1 ? '?' : '&', paramName, paramValue);
        }
    };

})();
/// Copyright (C) Microsoft Corporation. All rights reserved.

(function (jQuery)
{
    var w = window;
    var ME = w.MSA.MeControl;
    var $log = ME.Log;
    var $str = ME.Strings;

    ME.IFrameControl = new IFrameControl();
    /* @constructor */function IFrameControl()
    {
        /// <summary>
        /// Defines the IFrameControl class.
        /// </summary>

        var _this = this;
        var _disposed = false;

        var _frameIndex = 0;
        var _originToCallbackMap = {};

        function init()
        {
            /// <summary>
            /// Initializes the control
            /// </summary>

            jQuery(w).on('message.msame', handlePostMessage);
        }

        function openIFrameInternal(urlSource, fnCallback)
        {
            /// <summary>
            /// Opens an iframe and optionally adds a postMessage handler
            /// </summary>
            /// <param name="urlSource" type="String" />
            /// <param name="fnCallback" type="* -> void" />

            if (urlSource)
            {
                var startTime = Date.now();
                
                // adding a hidden iframe to the page
                var frameId = 'mecontrol_iframe_index_' + _frameIndex++;
                var iframe = jQuery('<iframe style="display:none"></iframe>')
                    .attr('id', frameId)
                    .attr('src', urlSource);
                iframe.appendTo('body');

                // if we have a callback function, add an entry to our domain map
                if (fnCallback)
                {
                    var origin = _this.getDomainFromUrl(urlSource);

                    if (!_originToCallbackMap[origin])
                    {
                        _originToCallbackMap[origin] = {};
                    }

                    _originToCallbackMap[origin][frameId] = { callback: fnCallback, iframe: iframe[0], start: startTime };
                }
            }
        }

        function handlePostMessage(e)
        {
            /// <summary>
            /// Handles the message event from the browser and routes it based on the origin
            /// </summary>
            /// <param name="e" type="*" />

            var originalEvent = e.originalEvent;

            if (originalEvent && _originToCallbackMap[originalEvent.origin])
            {
                jQuery.each(_originToCallbackMap[originalEvent.origin],
                    function (frameId, frameObj)
                    {
                        // we match the event window to the iframe window to route the event to the appropriate callback function
                        if (originalEvent.source == frameObj.iframe.contentWindow)
                        {
                            $log.logQos('IFrameCtrl', true, Date.now() - frameObj.start, '', { src: frameObj.iframe.src });
                            frameObj.callback(originalEvent);
                        }
                    }
                );
            }
        }

        _this.getDomainFromUrl = function (url)
        {
            /// <summary>
            /// Returns the root domain for a given url
            /// </summary>
            /// <param name="url" type="String" />
            /// <returns type="String" />

            var tmp = document.createElement('a');
            tmp.href = url;
            var domain = tmp.protocol + '//' + tmp.hostname;

            if ((tmp.port !== null) && (tmp.port !== '') && (tmp.port !== '443') && (tmp.port !== '80'))
            {
                domain += ':' + tmp.port;
            }

            return domain;
        };

        _this.openIFrame = function (urlSource, fnCallback, queryParams)
        {
            /// <summary>
            /// Opens an iframe and optionally adds a postMessage handler
            /// </summary>
            /// <param name="urlSource" type="String" />
            /// <param name="fnCallback" type="* -> void" />
            /// <param name="queryParams" type="*" optional="true"/>

            if (queryParams)
            {
                for (var param in queryParams)
                {
                    urlSource = ME.Util.appendQueryParameter(urlSource, param, queryParams[param]);
                }
            }

            openIFrameInternal(urlSource, fnCallback);
        };

        _this.dispose = function ()
        {
            /// <summary>
            /// Disposes the control
            /// </summary>

            if (!_disposed)
            {
                jQuery(w).off('message.msame');

                _this = null;
                _originToCallbackMap = null;

                _disposed = true;
            }
        };

        init();

        // Dispose on page unload
        jQuery(w).on('unload.msame', _this.dispose);
    }
})(window.MejQuery);
/// Copyright (C) Microsoft Corporation. All rights reserved.

(function (jQuery)
{
    var w = window;
    var ME = w.MSA.MeControl;
    var IFrameControl = ME.IFrameControl;
    var $log = ME.Log;

    var c_idpFlag = 'proxy'; 

    ME.UserStateModel = UserStateModel;
    /* @constructor */function UserStateModel(rpData)
    {
        /// <summary>
        /// Defines the UserStateModel class.
        /// </summary>
        /// <param type="ME.RPData">RP data for the control</param>

        var _this = this;
        var _disposed = false;

        var _rpData = rpData;

        var _userList = [];
        var /* @type(Array) */_cachedUserList = null;
        var /* @dynamic */_successCallback = null;
        var /* @dynamic */_failureCallback = null;
        var _timeout = 10000;

        var _expectedMessageCount = 0;
        var _fCallInProgress = false;
        var /* @type(Number) */_startTime;

        _this.currentState = function()
        {
            /// <summary>Gets the user's current state</summary>
            /// <returns type="Array">The list of current users</returns>
            
            return _cachedUserList || [];
        };

        function handlePostMessage(e)
        {
            /// <summary>
            /// General postMessage handler
            /// </summary>
            /// <param name="e" type="*" />

            // we only want to handle the postMessage if the call is in progress
            // for example, if the previous call timed out we don't want to trigger the callback if the call finally succeeds
            if (_fCallInProgress)
            {
                var isMsa = _rpData.msaInfo.meTrustedOrigin && e.origin === _rpData.msaInfo.meTrustedOrigin;
                var isAad = _rpData.aadInfo.meTrustedOrigin && e.origin === _rpData.aadInfo.meTrustedOrigin;

                // only proceed if the origin is trusted (comes from the same domain as the original iframe that was opened)
                if ((isMsa || isAad) && typeof e.data === 'string')
                {
                    _expectedMessageCount--;

                    var dataPoints = { currentIdp: isMsa ? ME.IDP.MSA : ME.IDP.AAD, messagesMissing: _expectedMessageCount };

                    var /* @dynamic */userData = jQuery.parseJSON(e.data);

                    if (userData && userData.userList && userData.userList.length > 0)
                    {
                        _userList.push.apply(_userList, userData.userList);
                    }
                    else
                    {
                        var errorCode = 'InvalidIdpData';
                        if (userData && userData.error)
                        {
                            dataPoints['IDPError'] = userData.error;
                            errorCode = 'IDPError';
                        }

                        $log.logQos('UserStatePartial', false, Date.now() - _startTime, errorCode, dataPoints);
                    }
                    
                    if (_expectedMessageCount === 0)
                    {
                        if (/* @static_cast(Boolean) */_userList && _userList.length > 0)
                        {
                            // Deliver partial results even if one IDP fails
                            notifyResult(true);
                        }
                        else
                        {
                            notifyResult(false, 'NoIdpData', dataPoints);
                        }
                    }
                }
            }
        }

        function notifyResult(success, errorCode, dataPoints)
        {
            /// <summary>Makes the necessary call back with the results</summary>
            /// <param name="success" type="Boolean">True if succeeded, false otherwise</param>
            /// <param name="errorCode" type="String" optional="true">An error code</param>
            /// <param name="dataPoints" type="*" optional="true">Collection of extra information to be logged</param>

            _cachedUserList = _userList || [];

            dataPoints = dataPoints || {};
            dataPoints['userCount'] = _cachedUserList.length;
            
            $log.logQos('UserState', success, Date.now() - _startTime, errorCode, dataPoints);

            if (success)
            {
                _successCallback(_userList);
            }
            else
            {
                _failureCallback && _failureCallback();
            }
            
            resetFlags();
        }

        function handleTimeout()
        {
            /// <summary>
            /// If the IFrames don't respond in a given time, we want to notify the caller of the timeout
            /// </summary>

            // if the call is still in progress, it means it has gone over the given time and we notify the caller
            if (_fCallInProgress)
            {
                if (/* @static_cast(Boolean) */_userList && _userList.length > 0)
                {
                    notifyResult(true, '', { timeout: true, messagesMissing: _expectedMessageCount });
                }
                else
                {
                    notifyResult(false, 'Timeout');
                }
            }
        }

        function resetFlags()
        {
            /// <summary>
            /// Reset all the flags and user data
            /// </summary>

            _expectedMessageCount = 0;
            _fCallInProgress = false;
            _startTime = 0;
            _userList = [];
        }

        _this.getUserState = function (successCallback, failureCallback, timeout)
        {
            /// <summary>
            /// Gets the user state
            /// </summary>
            /// <param name="successCallback" type="* -> void" />
            /// <param name="failureCallback" type="void -> void" />
            /// <param name="timeout" type="Number" optional="true" />

            _cachedUserList = null;
            _successCallback = successCallback;
            _failureCallback = failureCallback;
            _startTime = Date.now();
            
            ///#DEBUG
            /* @disable(0092) */
            if (ME.TestData)
            {
                setTimeout(function() {
                    _successCallback(ME.TestData);
                }, 0);
                return;
            }
            /* @enable(0092) */
            ///#ENDDEBUG
            
            if (!w.postMessage)
            {
                notifyResult(false, 'PostMessageNotSupported');
                return;
            }

            if (location.protocol !== 'https:')
            {
                notifyResult(false, 'HttpNotSupported');
                return;
            }

            if (timeout)
            {
                _timeout = timeout;
            }

            setTimeout(handleTimeout, _timeout);

            _fCallInProgress = true;
            _expectedMessageCount = 2;

            var queryParams = { uaid: $log.id };

            if (_rpData && _rpData.msaInfo && _rpData.aadInfo)
            {
                if (_rpData.msaInfo && _rpData.msaInfo.meUrl)
                {
                    _rpData.msaInfo.meTrustedOrigin = IFrameControl.getDomainFromUrl(_rpData.msaInfo.meUrl);

                    if (_rpData.aadInfo && _rpData.aadInfo.meUrl)
                    {
                        _rpData.aadInfo.meTrustedOrigin = IFrameControl.getDomainFromUrl(_rpData.aadInfo.meUrl);

                        // if both are supported, open 2 iframes
                        IFrameControl.openIFrame(_rpData.msaInfo.meUrl, handlePostMessage, queryParams);
                        IFrameControl.openIFrame(_rpData.aadInfo.meUrl, handlePostMessage, queryParams);
                    }
                    else
                    {
                        // if only MSA is supported, open the MSA iframe with a proxy to AAD
                        queryParams.idpflag = c_idpFlag;
                        IFrameControl.openIFrame(_rpData.msaInfo.meUrl, handlePostMessage, queryParams);
                    }
                }
                else if (_rpData.aadInfo && _rpData.aadInfo.meUrl)
                {
                    _rpData.aadInfo.meTrustedOrigin = IFrameControl.getDomainFromUrl(_rpData.aadInfo.meUrl);

                    // if only AAD is supported, open the AAD iframe with a proxy to AAD
                    queryParams.idpflag = c_idpFlag;
                    IFrameControl.openIFrame(_rpData.aadInfo.meUrl, handlePostMessage, queryParams);
                }
            }
            else
            {
                notifyResult(false, 'InvalidRpData');
            }
        };

        _this.dispose = function ()
        {
            /// <summary>
            /// Disposes the control
            /// </summary>

            if (!_disposed)
            {
                _disposed = true;
            }
        };
    }
})(window.MejQuery);
window.scriptsLoaded['suiteserviceproxyiframe.mouse.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['suiteserviceproxyiframe.mouse.js'] = (new Date()).getTime();
