/* Office JavaScript API library */
/* Version: 16.0.9320.1000 */
/*
	Copyright (c) Microsoft Corporation.  All rights reserved.
*/


/*
    Your use of this file is governed by the Microsoft Services Agreement http://go.microsoft.com/fwlink/?LinkId=266419.

    This file also contains the following Promise implementation (with a few small modifications):
        * @overview es6-promise - a tiny implementation of Promises/A+.
        * @copyright Copyright (c) 2014 Yehuda Katz, Tom Dale, Stefan Penner and contributors (Conversion to ES6 API by Jake Archibald)
        * @license   Licensed under MIT license
        *            See https://raw.githubusercontent.com/jakearchibald/es6-promise/master/LICENSE
        * @version   2.3.0
*/
var OSF=OSF||{};OSF.HostSpecificFileVersionDefault="16.00";OSF.HostSpecificFileVersionMap={access:{web:"16.00"},agavito:{winrt:"16.00"},excel:{ios:"16.00",mac:"16.00",web:"16.00",win32:"16.01",winrt:"16.00"},onenote:{web:"16.00",win32:"16.00",winrt:"16.00"},outlook:{ios:"16.00",mac:"16.00",web:"16.01",win32:"16.02"},powerpoint:{ios:"16.00",mac:"16.00",web:"16.00",win32:"16.01",winrt:"16.00"},project:{win32:"16.00"},sway:{web:"16.00"},word:{ios:"16.00",mac:"16.00",web:"16.00",win32:"16.01",winrt:"16.00"}};OSF.SupportedLocales={"ar-sa":true,"bg-bg":true,"bn-in":true,"ca-es":true,"cs-cz":true,"da-dk":true,"de-de":true,"el-gr":true,"en-us":true,"es-es":true,"et-ee":true,"eu-es":true,"fa-ir":true,"fi-fi":true,"fr-fr":true,"gl-es":true,"he-il":true,"hi-in":true,"hr-hr":true,"hu-hu":true,"id-id":true,"it-it":true,"ja-jp":true,"kk-kz":true,"ko-kr":true,"lo-la":true,"lt-lt":true,"lv-lv":true,"ms-my":true,"nb-no":true,"nl-nl":true,"nn-no":true,"pl-pl":true,"pt-br":true,"pt-pt":true,"ro-ro":true,"ru-ru":true,"sk-sk":true,"sl-si":true,"sr-cyrl-cs":true,"sr-cyrl-rs":true,"sr-latn-cs":true,"sr-latn-rs":true,"sv-se":true,"th-th":true,"tr-tr":true,"uk-ua":true,"ur-pk":true,"vi-vn":true,"zh-cn":true,"zh-tw":true};OSF.AssociatedLocales={ar:"ar-sa",bg:"bg-bg",bn:"bn-in",ca:"ca-es",cs:"cs-cz",da:"da-dk",de:"de-de",el:"el-gr",en:"en-us",es:"es-es",et:"et-ee",eu:"eu-es",fa:"fa-ir",fi:"fi-fi",fr:"fr-fr",gl:"gl-es",he:"he-il",hi:"hi-in",hr:"hr-hr",hu:"hu-hu",id:"id-id",it:"it-it",ja:"ja-jp",kk:"kk-kz",ko:"ko-kr",lo:"lo-la",lt:"lt-lt",lv:"lv-lv",ms:"ms-my",nb:"nb-no",nl:"nl-nl",nn:"nn-no",pl:"pl-pl",pt:"pt-br",ro:"ro-ro",ru:"ru-ru",sk:"sk-sk",sl:"sl-si",sr:"sr-cyrl-cs",sv:"sv-se",th:"th-th",tr:"tr-tr",uk:"uk-ua",ur:"ur-pk",vi:"vi-vn",zh:"zh-cn"};OSF.getSupportedLocale=function(a,c){if(c===void 0)c="en-us";if(!a)return c;var b;a=a.toLowerCase();if(a in OSF.SupportedLocales)b=a;else{var d=a.split("-",1);if(d&&d.length>0)b=OSF.AssociatedLocales[d[0]]}if(!b)b=c;return b};var ScriptLoading;(function(e){var a=false,b=function(){function b(g,e,d,f,c){var b=this;b.url=g;b.isReady=e;b.hasStarted=d;b.timer=f;b.hasError=a;b.pendingCallbacks=[];b.pendingCallbacks.push(c)}return b}(),d=function(){function a(c,b,a){this.scriptId=c;this.startTime=b;this.msResponseTime=a}return a}(),c=function(){var c=true,e=null;function f(){var a=this;a.defaultScriptLoadingTimeout=1e4;a.loadedScriptByIds={};a.scriptTelemetryBuffer=[];a.osfControlAppCorrelationId="";a.basePath=e;a.constantNames={OfficeJS:"office.js",OfficeDebugJS:"office.debug.js"}}f.prototype.isScriptLoading=function(a){return !!(this.loadedScriptByIds[a]&&this.loadedScriptByIds[a].hasStarted)};f.prototype.getOfficeJsBasePath=function(){var a=this;if(a.basePath)return a.basePath;else{for(var g=function(b,c){var d,a,e;e=b.toLowerCase();a=e.indexOf(c);if(a>=0&&a===b.length-c.length&&(a===0||b.charAt(a-1)==="/"||b.charAt(a-1)==="\\"))d=b.substring(0,a);else if(a>=0&&a<b.length-c.length&&b.charAt(a+c.length)==="?"&&(a===0||b.charAt(a-1)==="/"||b.charAt(a-1)==="\\"))d=b.substring(0,a);return d},d=document.getElementsByTagName("script"),h=d.length,e=[a.constantNames.OfficeJS,a.constantNames.OfficeDebugJS],f=e.length,c,b=0;!a.basePath&&b<h;b++)if(d[b].src)for(c=0;!a.basePath&&c<f;c++)a.basePath=g(d[b].src,e[c]);return a.basePath}};f.prototype.loadScript=function(e,d,c,a,b){this.loadScriptInternal(e,d,c,a,b)};f.prototype.loadScriptParallel=function(d,c,b){this.loadScriptInternal(d,c,e,a,b)};f.prototype.waitForFunction=function(g,e,h,i){var b=h,f,d=function(){b--;if(g()){e(c);return}else if(b>0){f=window.setTimeout(d,i);b--}else{window.clearTimeout(f);e(a)}};d()};f.prototype.waitForScripts=function(b,e){var f=this;if(this.invokeCallbackIfScriptsReady(b,e)==a)for(var c=0;c<b.length;c++){var g=b[c],d=this.loadedScriptByIds[g];d&&d.pendingCallbacks.push(function(){f.invokeCallbackIfScriptsReady(b,e)})}};f.prototype.logScriptLoading=function(c,a,b){a=Math.floor(a);if(OSF.AppTelemetry&&OSF.AppTelemetry.onScriptDone)if(OSF.AppTelemetry.onScriptDone.length==3)OSF.AppTelemetry.onScriptDone(c,a,b);else OSF.AppTelemetry.onScriptDone(c,a,b,this.osfControlAppCorrelationId);else{var e=new d(c,a,b);this.scriptTelemetryBuffer.push(e)}};f.prototype.setAppCorrelationId=function(a){this.osfControlAppCorrelationId=a};f.prototype.invokeCallbackIfScriptsReady=function(h,j){for(var g=a,f=0;f<h.length;f++){var i=h[f],d=this.loadedScriptByIds[i];if(!d){d=new b("",a,a,e,e);this.loadedScriptByIds[i]=d}if(d.isReady==a)return a;else if(d.hasError)g=c}j(!g);return c};f.prototype.getScriptEntryByUrl=function(c){for(var b in this.loadedScriptByIds){var a=this.loadedScriptByIds[b];if(this.loadedScriptByIds.hasOwnProperty(b)&&a.url===c)return a}return e};f.prototype.loadScriptInternal=function(h,g,i,n,k){var j=this;if(h){var q=j,r=window.document,d=g&&j.loadedScriptByIds[g]?j.loadedScriptByIds[g]:j.getScriptEntryByUrl(h);if(!d||d.hasError||d.url.toLowerCase()!=h.toLowerCase()){var f=r.createElement("script");f.type="text/javascript";if(g)f.id=g;if(!d){d=new b(h,a,a,e,e);j.loadedScriptByIds[g?g:h]=d}else{d.url=h;d.hasError=a;d.isReady=a}if(i)if(n)d.pendingCallbacks.unshift(i);else d.pendingCallbacks.push(i);var l=-1;if(window.performance&&window.performance.now)l=window.performance.now();var s=(new Date).getTime(),o=function(b){if(g){var a=(new Date).getTime()-s;if(!b)a=-a;q.logScriptLoading(g,l,a)}q.flushTelemetryBuffer()},m=function(){var b="undefined";if(OSF._OfficeAppFactory.getHostInfo().hostType=="onenote"&&typeof OSF.AppTelemetry!==b&&typeof OSF.AppTelemetry.enableTelemetry!==b)OSF.AppTelemetry.enableTelemetry=a;if(!OSF._OfficeAppFactory.getLoggingAllowed()&&typeof OSF.AppTelemetry!==b)OSF.AppTelemetry.enableTelemetry=a;o(c);d.isReady=c;if(d.timer!=e){clearTimeout(d.timer);delete d.timer}for(var h=d.pendingCallbacks.length,g=0;g<h;g++){var f=d.pendingCallbacks.shift();if(f){var i=f(c);if(i===a)break}}},p=function(){o(a);d.hasError=c;d.isReady=c;if(d.timer!=e){clearTimeout(d.timer);delete d.timer}for(var g=d.pendingCallbacks.length,f=0;f<g;f++){var b=d.pendingCallbacks.shift();if(b){var h=b(a);if(h===a)break}}};if(f.readyState)f.onreadystatechange=function(){if(f.readyState=="loaded"||f.readyState=="complete"){f.onreadystatechange=e;m()}};else f.onload=m;f.onerror=p;k=k||j.defaultScriptLoadingTimeout;d.timer=setTimeout(p,k);d.hasStarted=c;f.setAttribute("crossOrigin","anonymous");f.src=h;r.getElementsByTagName("head")[0].appendChild(f)}else if(d.isReady)i(c);else if(n)d.pendingCallbacks.unshift(i);else d.pendingCallbacks.push(i)}};f.prototype.flushTelemetryBuffer=function(){var b=this;if(OSF.AppTelemetry&&OSF.AppTelemetry.onScriptDone){for(var c=0;c<b.scriptTelemetryBuffer.length;c++){var a=b.scriptTelemetryBuffer[c];if(OSF.AppTelemetry.onScriptDone.length==3)OSF.AppTelemetry.onScriptDone(a.scriptId,a.startTime,a.msResponseTime);else OSF.AppTelemetry.onScriptDone(a.scriptId,a.startTime,a.msResponseTime,b.osfControlAppCorrelationId)}b.scriptTelemetryBuffer=[]}};return f}();e.LoadScriptHelper=c})(ScriptLoading||(ScriptLoading={}));var OfficeExt;(function(a){var b;(function(a){var b=function(){function a(){var a=this;a.getDiagnostics=function(b){var a={host:this.getHost(),version:b||this.getDefaultVersion(),platform:this.getPlatform()};return a};a.platformRemappings={web:Microsoft.Office.WebExtension.PlatformType.OfficeOnline,winrt:Microsoft.Office.WebExtension.PlatformType.Universal,win32:Microsoft.Office.WebExtension.PlatformType.PC,mac:Microsoft.Office.WebExtension.PlatformType.Mac,ios:Microsoft.Office.WebExtension.PlatformType.iOS,android:Microsoft.Office.WebExtension.PlatformType.Android};a.camelCaseMappings={powerpoint:Microsoft.Office.WebExtension.HostType.PowerPoint,onenote:Microsoft.Office.WebExtension.HostType.OneNote};a.hostInfo=OSF._OfficeAppFactory.getHostInfo();a.getHost=a.getHost.bind(a);a.getPlatform=a.getPlatform.bind(a);a.getDiagnostics=a.getDiagnostics.bind(a)}a.prototype.capitalizeFirstLetter=function(a){if(a)return a[0].toUpperCase()+a.slice(1).toLowerCase();return a};a.getInstance=function(){if(a.hostObj===undefined)a.hostObj=new a;return a.hostObj};a.prototype.getPlatform=function(){var a=this;if(a.hostInfo.hostPlatform){var b=a.hostInfo.hostPlatform.toLowerCase();if(a.platformRemappings[b])return a.platformRemappings[b]}return null};a.prototype.getHost=function(){var a=this;if(a.hostInfo.hostType){var b=a.hostInfo.hostType.toLowerCase();if(a.camelCaseMappings[b])return a.camelCaseMappings[b];b=a.capitalizeFirstLetter(a.hostInfo.hostType);if(Microsoft.Office.WebExtension.HostType[b])return Microsoft.Office.WebExtension.HostType[b]}return null};a.prototype.getDefaultVersion=function(){if(this.getHost())return "16.0.0000.0000";return null};return a}();a.Host=b})(b=a.HostName||(a.HostName={}))})(OfficeExt||(OfficeExt={}));var Office;(function(d){var a=true,b="undefined",c="function",e;(function(d){var e;(function(d){function e(){return function(){var d=null,e="object";"use strict";function R(a){return typeof a===c||typeof a===e&&a!==d}function y(a){return typeof a===c}function U(a){return typeof a===e&&a!==d}var z;if(!Array.isArray)z=function(a){return Object.prototype.toString.call(a)==="[object Array]"};else z=Array.isArray;var E=z,r=0,pb={}.toString,kb,w,l=function(a,b){q[r]=a;q[r+1]=b;r+=2;if(r===2)if(w)w(p);else s()};function db(a){w=a}function mb(a){l=a}var Y=typeof window!==b?window:undefined,D=Y||{},A=D.MutationObserver||D.WebKitMutationObserver,nb=typeof process!==b&&{}.toString.call(process)==="[object process]",lb=typeof Uint8ClampedArray!==b&&typeof importScripts!==b&&typeof MessageChannel!==b;function fb(){var b=process.nextTick,a=process.versions.node.match(/^(?:(\d+)\.)?(?:(\d+)\.)?(\*|\d+)$/);if(Array.isArray(a)&&a[1]==="0"&&a[2]==="10")b=setImmediate;return function(){b(p)}}function M(){var b=0,d=new A(p),c=document.createTextNode("");d.observe(c,{characterData:a});return function(){c.data=b=++b%2}}function P(){var a=new MessageChannel;a.port1.onmessage=p;return function(){a.port2.postMessage(0)}}function Z(){return function(){setTimeout(p,1)}}var q=new Array(1e3);function p(){for(var a=0;a<r;a+=2){var b=q[a],c=q[a+1];b(c);q[a]=undefined;q[a+1]=undefined}r=0}var s;if(nb)s=fb();else if(A)s=M();else if(lb)s=P();else s=Z();function o(){}var k=void 0,m=1,j=2,t=new C;function K(){return new TypeError("You cannot resolve a promise with itself")}function L(){return new TypeError("A promises callback cannot return that same promise.")}function bb(b){try{return b.then}catch(a){t.error=a;return t}}function cb(e,d,b,c){try{e.call(d,b,c)}catch(a){return a}}function F(c,b,d){l(function(e){var c=false,g=cb(d,b,function(d){if(c)return;c=a;if(b!==d)n(e,d);else h(e,d)},function(b){if(c)return;c=a;f(e,b)},"Settle: "+(e._label||" unknown promise"));if(!c&&g){c=a;f(e,g)}},c)}function H(b,a){if(a._state===m)h(b,a._result);else if(a._state===j)f(b,a._result);else u(a,undefined,function(a){n(b,a)},function(a){f(b,a)})}function G(b,a){if(a.constructor===b.constructor)H(b,a);else{var c=bb(a);if(c===t)f(b,t.error);else if(c===undefined)h(b,a);else if(y(c))F(b,a,c);else h(b,a)}}function n(a,b){if(a===b)f(a,K());else if(R(b))G(a,b);else h(a,b)}function J(a){a._onerror&&a._onerror(a._result);x(a)}function h(a,b){if(a._state!==k)return;a._result=b;a._state=m;a._subscribers.length!==0&&l(x,a)}function f(a,b){if(a._state!==k)return;a._state=j;a._result=b;l(J,a)}function u(c,g,e,f){var a=c._subscribers,b=a.length;c._onerror=d;a[b]=g;a[b+m]=e;a[b+j]=f;b===0&&c._state&&l(x,c)}function x(b){var a=b._subscribers,f=b._state;if(a.length===0)return;for(var e,d,g=b._result,c=0;c<a.length;c+=3){e=a[c];d=a[c+f];if(e)B(f,e,d,g);else d(g)}b._subscribers.length=0}function C(){this.error=d}var v=new C;function X(b,c){try{return b(c)}catch(a){v.error=a;return v}}function B(l,c,i,o){var g=y(i),b,q,e,p;if(g){b=X(i,o);if(b===v){p=a;q=b.error;b=d}else e=a;if(c===b){f(c,L());return}}else{b=o;e=a}if(c._state===k)if(g&&e)n(c,b);else if(p)f(c,q);else if(l===m)h(c,b);else l===j&&f(c,b)}function I(a,c){try{c(function(b){n(a,b)},function(b){f(a,b)})}catch(b){f(a,b)}}function i(c,b){var a=this;a._instanceConstructor=c;a.promise=new c(o);if(a._validateInput(b)){a._input=b;a.length=b.length;a._remaining=b.length;a._init();if(a.length===0)h(a.promise,a._result);else{a.length=a.length||0;a._enumerate();a._remaining===0&&h(a.promise,a._result)}}else f(a.promise,a._validationError())}i.prototype._validateInput=function(a){return E(a)};i.prototype._validationError=function(){return new Error("Array Methods must be provided an Array")};i.prototype._init=function(){this._result=new Array(this.length)};var ab=i;i.prototype._enumerate=function(){for(var a=this,d=a.length,c=a.promise,e=a._input,b=0;c._state===k&&b<d;b++)a._eachEntry(e[b],b)};i.prototype._eachEntry=function(a,c){var b=this,e=b._instanceConstructor;if(U(a))if(a.constructor===e&&a._state!==k){a._onerror=d;b._settledAt(a._state,c,a._result)}else b._willSettleAt(e.resolve(a),c);else{b._remaining--;b._result[c]=a}};i.prototype._settledAt=function(d,e,c){var a=this,b=a.promise;if(b._state===k){a._remaining--;if(d===j)f(b,c);else a._result[e]=c}a._remaining===0&&h(b,a._result)};i.prototype._willSettleAt=function(c,b){var a=this;u(c,undefined,function(c){a._settledAt(m,b,c)},function(c){a._settledAt(j,b,c)})};function jb(a){return (new ab(this,a)).promise}var W=jb;function eb(b){var d=this,a=new d(o);if(!E(b)){f(a,new TypeError("You must pass an array to race."));return a}var h=b.length;function e(b){n(a,b)}function g(b){f(a,b)}for(var c=0;a._state===k&&c<h;c++)u(d.resolve(b[c]),undefined,e,g);return a}var V=eb;function O(a){var b=this;if(a&&typeof a===e&&a.constructor===b)return a;var c=new b(o);n(c,a);return c}var N=O;function T(c){var b=this,a=new b(o);f(a,c);return a}var Q=T,hb=0;function S(){throw new TypeError("You must pass a resolver function as the first argument to the promise constructor")}function gb(){throw new TypeError("Failed to construct 'Promise': Please use the 'new' operator, this object constructor cannot be called as a function.")}var ib=g;function g(b){var a=this;a._id=hb++;a._state=undefined;a._result=undefined;a._subscribers=[];if(o!==b){!y(b)&&S();!(a instanceof g)&&gb();I(a,b)}}g.all=W;g.race=V;g.resolve=N;g.reject=Q;g._setScheduler=db;g._setAsap=mb;g._asap=l;g.prototype={constructor:g,then:function(d,e){var b=this,a=b._state;if(a===m&&!d||a===j&&!e)return this;var c=new this.constructor(o),g=b._result;if(a){var f=arguments[a-1];l(function(){B(a,c,f,g)})}else u(b,c,d,e);return c},"catch":function(a){return this.then(d,a)}};return ib}.call(this)}d.Init=e})(e=d.PromiseImpl||(d.PromiseImpl={}))})(e=d._Internal||(d._Internal={}));var e;(function(d){function f(){var b=window.navigator.userAgent,c=b.indexOf("Edge/");if(c>=0){b=b.substring(c+5,b.length);if(b<"14.14393")return a;else return false}return false}function e(){if(typeof window===b&&typeof Promise===c)return Promise;if(typeof window!==b&&window.Promise)if(f())return d.PromiseImpl.Init();else return window.Promise;else return d.PromiseImpl.Init()}d.OfficePromise=e()})(e=d._Internal||(d._Internal={}));var f=e.OfficePromise;d.Promise=f})(Office||(Office={}));OSF.ConstantNames={FileVersion:"16.0.9320.1000",OfficeJS:"office.js",OfficeDebugJS:"office.debug.js",DefaultLocale:"en-us",LocaleStringLoadingTimeout:5e3,MicrosoftAjaxId:"MSAJAX",OfficeStringsId:"OFFICESTRINGS",OfficeJsId:"OFFICEJS",HostFileId:"HOST",O15MappingId:"O15Mapping",OfficeStringJS:"office_strings.js",O15InitHelper:"o15apptofilemappingtable.js",SupportedLocales:OSF.SupportedLocales,AssociatedLocales:OSF.AssociatedLocales};OSF.InitializationHelper=function(d,b,f,e,c){var a=this;a._hostInfo=d;a._webAppState=b;a._context=f;a._settings=e;a._hostFacade=c};OSF.InitializationHelper.prototype.saveAndSetDialogInfo=function(){};OSF.InitializationHelper.prototype.getAppContext=function(){};OSF.InitializationHelper.prototype.setAgaveHostCommunication=function(){};OSF.InitializationHelper.prototype.prepareRightBeforeWebExtensionInitialize=function(){};OSF.InitializationHelper.prototype.loadAppSpecificScriptAndCreateOM=function(){};OSF.InitializationHelper.prototype.prepareRightAfterWebExtensionInitialize=function(){};OSF._OfficeAppFactory=function(){var l="_host_Info",c="undefined",h="function",f="",b=true,d=false,e=null,n=function(b,a){if(a&&b&&!a[b])a[b]={}};n("Office",window);n("Microsoft",window);n("Office",Microsoft);n("WebExtension",Microsoft.Office);if(window.Office.Promise)Microsoft.Office.WebExtension.Promise=window.Office.Promise;window.Office=Microsoft.Office.WebExtension;Microsoft.Office.WebExtension.PlatformType={PC:"PC",OfficeOnline:"OfficeOnline",Mac:"Mac",iOS:"iOS",Android:"Android",Universal:"Universal"};Microsoft.Office.WebExtension.HostType={Word:"Word",Excel:"Excel",PowerPoint:"PowerPoint",Outlook:"Outlook",OneNote:"OneNote",Project:"Project",Access:"Access"};var q={},E={},p={},j={id:e,webAppUrl:e,conversationID:e,clientEndPoint:e,wnd:window.parent,focused:d},a={isO15:b,isRichClient:b,hostType:f,hostPlatform:f,hostSpecificFileVersion:f,hostLocale:f,osfControlAppCorrelationId:f,isDialog:d,disableLogging:d},k=b,i={},u=e,t=d,m=[],g=new ScriptLoading.LoadScriptHelper;window.performance&&window.performance.now&&g.logScriptLoading(OSF.ConstantNames.OfficeJsId,-1,window.performance.now());var y=window.location.hash,x=window.location.search,v=window.name,s=function(a){return {host:OfficeExt.HostName.Host.getInstance().getHost(a),platform:OfficeExt.HostName.Host.getInstance().getPlatform(a)}},r=function(a){var d=a.host,c=a.platform;t=b;while(m.length>0)m.shift()({host:d,platform:c})};Microsoft.Office.WebExtension.onReady=function(a){if(t){var e=s(1),d=e.host,c=e.platform;if(a){var b=a({host:d,platform:c});if(b&&b.then&&typeof b.then===h)return b.then(function(){return Office.Promise.resolve({host:d,platform:c})})}return Office.Promise.resolve({host:d,platform:c})}if(a)return new Office.Promise(function(b){m.push(function(d){var c=a(d);if(c&&c.then&&typeof c.then===h)return c.then(function(){return b(d)});b(d)})});return new Office.Promise(function(a){m.push(a)})};var o=function(g){var c,d=window.location.search;if(d){var b=d.split(g+"=");if(b.length>1){var e=b[1],f=new RegExp("[&#]","g"),a=e.split(f);if(a.length>0)c=a[0]}}return c},C=function(f,g){var c=f.split("."),e=g.split("."),a;for(a in c)if(parseInt(c[a])<parseInt(e[a]))return d;else if(parseInt(c[a])>parseInt(e[a]))return b;return d},A=function(){var b="15.30.1128.0",a=window.external.GetContext().GetHostFullVersion();return !!C(b,a)},w=function(){k=b;try{if(a.disableLogging){k=d;return}window.external=window.external||{};if(typeof window.external.GetLoggingAllowed===c)k=b;else k=window.external.GetLoggingAllowed()}catch(e){}},B=function(){var i="hostInfoValue",m="isDialog",p=l,h=o(p);if(!h)try{var r=JSON.parse(v);h=r?r["hostInfo"]:e}catch(s){}if(!h)try{window.external=window.external||{};if(typeof agaveHost!==c&&agaveHost.GetHostInfo)window.external.GetHostInfo=function(){return agaveHost.GetHostInfo()};var k=window.external.GetHostInfo();if(k==m){a.isO15=b;a.isDialog=b}else if(k.toLowerCase().indexOf("mac")!==-1&&k.toLowerCase().indexOf("outlook")!==-1&&A())a.isO15=b;else{var q=k.split(p+"=");if(q.length>1)h=q[1];else h=k}}catch(s){}var u=function(){var a=e;try{if(window.sessionStorage)a=window.sessionStorage}catch(b){}return a},j=u();if(!h&&j&&j.getItem(i))h=j.getItem(i);if(h){h=decodeURIComponent(h);a.isO15=d;var g=h.split("$");if(typeof g[2]==c)g=h.split("|");a.hostType=typeof g[0]==c?f:g[0].toLowerCase();a.hostPlatform=typeof g[1]==c?f:g[1].toLowerCase();a.hostSpecificFileVersion=typeof g[2]==c?f:g[2].toLowerCase();a.hostLocale=typeof g[3]==c?f:g[3].toLowerCase();a.osfControlAppCorrelationId=typeof g[4]==c?f:g[4];if(a.osfControlAppCorrelationId=="telemetry")a.osfControlAppCorrelationId=f;a.isDialog=typeof g[5]!=c&&g[5]==m?b:d;a.disableLogging=typeof g[6]!=c&&g[6]=="disableLogging"?b:d;var t=parseFloat(a.hostSpecificFileVersion),n=OSF.HostSpecificFileVersionDefault;if(OSF.HostSpecificFileVersionMap[a.hostType]&&OSF.HostSpecificFileVersionMap[a.hostType][a.hostPlatform])n=OSF.HostSpecificFileVersionMap[a.hostType][a.hostPlatform];if(t>parseFloat(n))a.hostSpecificFileVersion=n;if(j)try{j.setItem(i,h)}catch(w){}}else{a.isO15=b;a.hostLocale=o("locale")}},z=function(b,a){OSF.AppTelemetry&&OSF.AppTelemetry.logAppCommonMessage&&OSF.AppTelemetry.logAppCommonMessage("getAppContextAsync starts");i.getAppContext(b,a)},D=function(){B();w();if(a.hostPlatform=="web"&&a.isDialog&&window==window.top&&window.opener==e){window.open(f,"_self",f);window.close()}g.setAppCorrelationId(a.osfControlAppCorrelationId);var k=g.getOfficeJsBasePath(),C=d;if(!k)throw"Office Web Extension script library file name should be "+OSF.ConstantNames.OfficeJS+" or "+OSF.ConstantNames.OfficeDebugJS+".";var m=function(){if(typeof Sys!==c&&typeof Type!==c&&Sys.StringBuilder&&typeof Sys.StringBuilder===h&&Type.registerNamespace&&typeof Type.registerNamespace===h&&Type.registerClass&&typeof Type.registerClass===h||typeof OfficeExt!==c&&OfficeExt.MsAjaxError)return b;else return d},n=e,x=function(f){var a=d,e=function(){if(typeof Strings==c||typeof Strings.OfficeOM==c)if(!a){a=b;var h=k+OSF.ConstantNames.DefaultLocale+"/"+OSF.ConstantNames.OfficeStringJS;g.loadScript(h,OSF.ConstantNames.OfficeStringsId,e,b,OSF.ConstantNames.LocaleStringLoadingTimeout);return d}else throw"Neither the locale, "+f.toLowerCase()+", provided by the host app nor the fallback locale "+OSF.ConstantNames.DefaultLocale+" are supported.";else{a=d;n=Strings.OfficeOM}};if(!m()){window.Type=Function;Type.registerNamespace=function(a){window[a]=window[a]||{}};Type.prototype.registerClass=function(a){a={}}}var h=k+OSF.getSupportedLocale(f,OSF.ConstantNames.DefaultLocale)+"/"+OSF.ConstantNames.OfficeStringJS;g.loadScript(h,OSF.ConstantNames.OfficeStringsId,e,b,OSF.ConstantNames.LocaleStringLoadingTimeout)},t=function(t){if(t){i=new OSF.InitializationHelper(a,j,q,E,p);a.hostPlatform=="web"&&i.saveAndSetDialogInfo&&i.saveAndSetDialogInfo(o(l));i.setAgaveHostCommunication();z(j.wnd,function(b){OSF.AppTelemetry&&OSF.AppTelemetry.logAppCommonMessage&&OSF.AppTelemetry.logAppCommonMessage("getAppContextAsync callback start");u=b._appInstanceId;var c=function(){var c=a.hostSpecificFileVersion.split(".");if(b.get_appMinorVersion){var d=a.hostPlatform=="ios";if(!d)if(isNaN(b.get_appMinorVersion()))b._appMinorVersion=parseInt(c[1]);else if(c.length>1&&!isNaN(Number(c[1])))b._appMinorVersion=parseInt(c[1])}if(a.isDialog)b._isDialog=a.isDialog};c();var d=function(){i.prepareApiSurface&&i.prepareApiSurface(b);g.waitForFunction(function(){return Microsoft.Office.WebExtension.initialize!=undefined},function(a){if(a){if(i.prepareApiSurface)Microsoft.Office.WebExtension.initialize(i.getInitializationReason(b));else i.prepareRightBeforeWebExtensionInitialize(b);i.prepareRightAfterWebExtensionInitialize&&i.prepareRightAfterWebExtensionInitialize()}else throw"Office.js has not been fully loaded yet. Please try again later or make sure to add your initialization code on the Office.initialize function."},400,50);r(s(b.get_appName()))};!g.isScriptLoading(OSF.ConstantNames.OfficeStringsId)&&x(b.get_appUILocale());g.waitForScripts([OSF.ConstantNames.OfficeStringsId],function(){if(n&&!Strings.OfficeOM)Strings.OfficeOM=n;i.loadAppSpecificScriptAndCreateOM(b,d,k)})});if(a.isO15){var m=OSF.OUtil.parseXdmInfo()==e;if(m){var f=b;if(window.external&&typeof window.external.GetContext!==c)try{window.external.GetContext();f=d}catch(v){}f&&r({host:e,platform:e})}}}else{var h="MicrosoftAjax.js is not loaded successfully.";OSF.AppTelemetry&&OSF.AppTelemetry.logAppException&&OSF.AppTelemetry.logAppException(h);throw h}},y=function(){OSF.AppTelemetry&&OSF.AppTelemetry.setOsfControlAppCorrelationId&&OSF.AppTelemetry.setOsfControlAppCorrelationId(a.osfControlAppCorrelationId);if(g.isScriptLoading(OSF.ConstantNames.MicrosoftAjaxId))g.waitForScripts([OSF.ConstantNames.MicrosoftAjaxId],t);else g.waitForFunction(m,t,500,100)};if(a.isO15)g.loadScript(k+OSF.ConstantNames.O15InitHelper,OSF.ConstantNames.O15MappingId,y);else{var v;v=a.hostType+"-"+a.hostPlatform+"-"+a.hostSpecificFileVersion+".js";g.loadScript(k+v.toLowerCase(),OSF.ConstantNames.HostFileId,y)}a.hostLocale&&x(a.hostLocale);if(C&&!m()){var D=(window.location.protocol.toLowerCase()==="https:"?"https:":"http:")+"//ajax.aspnetcdn.com/ajax/3.5/MicrosoftAjax.js";g.loadScriptParallel(D,OSF.ConstantNames.MicrosoftAjaxId)}window.confirm=function(){throw"Function window.confirm is not supported.";return d};window.alert=function(){throw"Function window.alert is not supported."};window.prompt=function(){throw"Function window.prompt is not supported.";return e};var A=a.hostType=="outlook"&&a.hostPlatform=="android";if(!A){window.history.replaceState=e;window.history.pushState=e}};D();return {getId:function(){return j.id},getClientEndPoint:function(){return j.clientEndPoint},getContext:function(){return q},setContext:function(a){q=a},getHostInfo:function(){return a},getLoggingAllowed:function(){return k},getHostFacade:function(){return p},setHostFacade:function(a){p=a},getInitializationHelper:function(){return i},getCachedSessionSettingsKey:function(){return (j.conversationID!=e?j.conversationID:u)+"CachedSessionSettings"},getWebAppState:function(){return j},getWindowLocationHash:function(){return y},getWindowLocationSearch:function(){return x},getLoadScriptHelper:function(){return g},getWindowName:function(){return v}}}()