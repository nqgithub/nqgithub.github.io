﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.core.locationcommon.js'] = (new Date()).getTime();
Type.registerNamespace("_lc");_lc.c=function(){};_lc.c.registerInterface("_lc.c");_lc.f=function(){};function LocationCommonComponent(){}LocationCommonComponent.$$cctor=function(){_a.t.a().a(LocationCommonComponent)};LocationCommonComponent.prototype={b:function(n,t,i){if(!t.a()){n.e(_a.gc).b(_a.E).a();t.b()?n.e(_lc.d).b(_lc.c).a():n.e(_lc.e).b(_lc.c).a();var u=this;n.b(_a.r,function(){return new _a.r(i.a())}).a()}var r=this;n.b(_lc.a,function(){return new _lc.a(n.a(_lc.c))}).a()},a:function(){return LocationCommonComponent.a}};_lc.a=function(n){this.c=n;this.a=!1};_lc.a.prototype={c:null,a:!1,b:function(n,t){if(this.a){t(new _lc.b(2,"Concurrent position requests are not allowed"));return}this.a=!0;var i=new _lc.f;i.accuracy=1;i.maximumAge=0;i.timeout=3e4;var u=this,r=this;this.c.a(function(t){if(u.a){u.e();u.g(t);n(t)}},function(n){if(r.a){r.e();r.f(n);t(n)}},i)},e:function(){this.a=!1;this.c.b()},g:function(n){this.d(n.a.e.toString(),"NA","NA")},f:function(n){var t=null;n.a===1?t="PermissionDenied":n.a===2?t="PositionUnavailable":n.a===3&&(t="Timeout");this.d("-1",t,n.b)},d:function(n,t,i){var u=_a.b.b(_a.a.b,"UserLocationMetadata",!1,null);var r=new _a.l;r.b("Accuracy",n);r.b("Error",t);r.b("Message",i);u.m=r.toString();_a.b.a(u)}};_lc.d=function(){};_lc.d.a=function(n){var t={};t.maximumAge=n.maximumAge;t.timeout=n.timeout;t.enableHighAccuracy=n.accuracy?!1:!0;return t};_lc.d.prototype={c:0,a:function(n,t,i){var u=this,r=this;this.c=navigator.geolocation.watchPosition(function(t){n(_a.bE.d(t))},function(n){t(_lc.b.a(n))},_lc.d.a(i))},b:function(){navigator.geolocation.clearWatch(this.c)}};_lc.e=function(){};_lc.e.prototype={a:function(n,t,i){var r=new _lc.b(1,"No Location Service Found");t(r)},b:function(){}};_lc.b=function(n,t){this.a=n;this.b=t};_lc.b.a=function(n){_a.c.a(n,"e");var t=2;n.code===1?t=1:n.code===2?t=2:n.code===3&&(t=3);return new _lc.b(t,n.message)};_lc.b.prototype={a:0,b:null};LocationCommonComponent.registerClass("LocationCommonComponent",null,_a.ki,_j.ce);_lc.a.registerClass("_lc.a");_lc.d.registerClass("_lc.d",null,_lc.c);_lc.e.registerClass("_lc.e",null,_lc.c);LocationCommonComponent.a=new Array(0);LocationCommonComponent.$$cctor();
window.scriptsLoaded['microsoft.owa.core.locationcommon.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.core.locationcommon.js'] = (new Date()).getTime();
