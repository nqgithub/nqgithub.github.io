﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.triageshared.js'] = (new Date()).getTime();
function TriageSharedComponent(){}TriageSharedComponent.$$cctor=function(){_a.t.a().a(TriageSharedComponent)};TriageSharedComponent.prototype={b:function(n,t,i){var f=this;n.b(_y.eZ,function(){return new _trs.b(n.a(_a.e),n.a(_g.h),n.a(_j.j))}).b(_y.eZ);var u=this;n.b(_y.gC,function(){return new _trs.f(n.a(_a.S),n.a(_a.e),n.a(_a.dN),n.a(_a.Z),n.a(_g.bI),n.a(_a.cK))}).b(_y.gC).a();var r=this;n.b(_y.gx,function(){var i=n.a(_a.e);if(i&&i.a().dA().Enabled){var u=n.a(_a.I);var t=u.a.mcuPercentage;var r=_j.h.b(t)?null:parseInt(t);return new _trs.j(n.a(_y.cE),n.a(_y.G),r)}return null}).a()},a:function(){return[]}};Type.registerNamespace("_trs");_trs.c=function(n){this.a=n};_trs.c.a=function(n,t,i,r,u){var o=n>=1073741824?1073741824:n>=1048576?1048576:1024;var e=(n/o).toFixed(u);var f=n>=1073741824?t:n>=1048576?i:r;return _j.h.c(f,e)};_trs.c.prototype={a:null,b:function(){var n=this.a.b();var i=this.a.c();var t=i.bH.UseDatabaseQuotaDefaults?n.e():i.c();return t.bH.IsUnlimited?n.b().bH.IsUnlimited?100:n.b().bH.Value>0?3:0:Math.round(n.b().bH.Value/t.bH.Value*100)},f:function(){var i=this.a.b();var t=this.a.c();var n=t.bH.UseDatabaseQuotaDefaults?i.c():t.b();var r=i.b().bH.Value;return n.bH.IsUnlimited?_ops.b.cS:this.d()?_trs.c.a(n.bH.Value,_ops.b.bQ,_ops.b.YC,_ops.b.VC,2):_trs.c.a(n.bH.Value,_ops.b.YL,_ops.b.cH,_ops.b.Fx,2)},e:function(){var i=this.a.b();var t=this.a.c();var n=t.bH.UseDatabaseQuotaDefaults?i.e():t.c();return n.bH.IsUnlimited?_ops.b.SH:_trs.c.a(n.bH.Value,_ops.b.ED,_ops.b.N,_ops.b.dz,2)},c:function(n,t,i){var u=this.a.b();var r=u.b().bH.Value;return _trs.c.a(r,n,t,i,2)},g:function(){if(!this.d())return null;var t=this.a.b();var n=this.a.c();var r=n.bH.UseDatabaseQuotaDefaults?t.c():n.b();var i=t.b().bH.Value-r.bH.Value;return _trs.c.a(i,_ops.b.Pf,_ops.b.gs,_ops.b.bs,2)},d:function(){var i=this.a.b();var t=this.a.c();var n=t.bH.UseDatabaseQuotaDefaults?i.c():t.b();var r=i.b().bH.Value;return!n.bH.IsUnlimited&&r>=n.bH.Value}};_trs.j=function(n,t,i){this.k=Function.createDelegate(this,this.a);this.f=Function.createDelegate(this,this.t);this.n=Function.createDelegate(this,this.u);this.m=Function.createDelegate(this,this.s);this.l=Function.createDelegate(this,this.r);this.e=n;this.i=t;this.h=new _j.g(this.l,_a.a.p);this.j=i!=null?i:95};_trs.j.prototype={e:null,i:null,j:0,b:0,d:null,h:null,c:null,g:!1,p:function(){var n=this.b>=98?_ops.b.Ro:_ops.b.FN;return _j.h.c(_ops.b.Ed,this.b,n)},q:function(){return this.b>=98?1:0},a:function(){var n=new _trs.i;n.c(this.m);_a.g.a.a(n)},s:function(n){var i=n;var t=new _trs.c(i.e);this.b=t.b();!this.g&&this.b>=this.j?this.v():this.o()},v:function(){this.e.b(this.n,this.f,this.q(),this.p(),null,_ops.b.XD,this.h,null,null,null,null,_fm.a.v,this.d,!1,null,!1,null)},u:function(n){this.d=n;this.c||(this.c=_j.m.a().e(_a.a.p,"MailboxUsageNotificationViewModel",this.k,5e3));_a.b.c(_a.a.p,"VM.MailboxCleanup.ShowMailboxUsage",this.b.toString(),0)},o:function(){this.e.a(this.d,this.f)},t:function(){this.d=null;if(this.c){this.c=_j.m.a().b(this.c);this.g=!0}_a.b.c(_a.a.p,"VM.MailboxCleanup.HideMailboxUsage")},r:function(){this.i.a(1450,1);this.o();_a.b.c(_a.a.p,"VM.MailboxCleanup.CleanupMailboxButtonClicked")}};_trs.b=function(n,t,i){this.g=i;if(n){var u=t.b().h();this.h=u.b()===_trs.b.a.b();if(!_trs.b.c&&this.h){_trs.b.c=!0;for(var r=0;r<_trs.b.a.b();r++)if(u.a(r)!==_trs.b.a.a(r)){_h.h.a(_a.a.W,"CustomHoverActions",-1,0,null);break}}}};_trs.b.prototype={g:null,h:!1,j:null,b:function(n){var i=_g.a.a().b().h();var r=new _a.k;if(this.h)for(var t=0;t<i.b();t++)i.a(t)&&r.c(i.a(t));else r=_trs.b.a;return this.i(r,n)},f:function(n,t){var u=_g.a.a().b().h();var i=new _a.k;if(this.h)if(_g.x.isInstanceOfType(n))for(var r=0;r<u.b();r++)u.a(r)&&i.c(u.a(r));else u.j(1)&&i.c(1);else _g.x.isInstanceOfType(n)?i=_trs.b.a:i.c(1);return this.i(i,t)},e:function(n){var u=_g.a.a().b().h();var t=new _a.k;if(this.h)for(var r=0;r<u.b();r++){var i=u.a(r);(i===4||i===1||i===5)&&t.c(i)}else{t.c(5);t.c(4);t.c(1)}return this.i(t,n)},d:function(n,t){for(var u=this.h?_g.a.a().b().h():_trs.b.b,f=new _a.k,i=0;i<u.b();i++){var r=u.a(i);(_g.x.isInstanceOfType(n)&&r===4||r===1)&&f.c(r)}return this.i(f,t)},c:function(n,t){for(var u=this.h?_g.a.a().b().h():_trs.b.b,f=new _a.k,i=0;i<u.b();i++){var r=u.a(i);(_g.x.isInstanceOfType(n)&&r===4||r===1)&&f.c(r)}return this.i(f,t)},a:function(n){var t=_trs.b.d;return this.i(t,n)},i:function(n,t){var r=new _j.l;if(t&&_a.gd.isInstanceOfType(t)&&t.fm)r.a(this.k(t));else for(var i=0;i<n.b();i++)r.a(this.l(n.a(i),t));return r},l:function(n,t){var i;switch(n){case 1:i=new _trs.g(this.g,t,1,t.U(),_n.b.U(),_n.b.bk(),_u.R.NG,null,null);break;case 2:i=new _trs.g(this.g,t,2,t.b(),_n.b.ck(),_n.b.dI(),_u.R.FG,null,null);break;case 5:var f=new _fce.f(new _b.a(_a.n.a(),_j.m.a()),this.g,_y.c.a,_g.a.a());f.c(t.q());f.j(!!t.q()&&t.q().q());var e=_y.hK.isInstanceOfType(t)?t.e():null;i=new _trs.g(this.g,t,5,t.ba(),t.W(),t.V(),t.X(),f,e);break;case 3:var r=t;i=new _trs.g(this.g,t,3,r.f(),r.d(),r.c(),r.a(),null,null);break;case 6:var o=t;var u=new _fce.f(new _b.a(_a.n.a(),_j.m.a()),this.g,_y.c.a,_g.a.a());u.e=!0;u.b=1;i=new _trs.g(this.g,t,6,o.e(),_n.b.cA(),_n.b.eE(),_u.R.Ls,u,null);break;case 4:i=new _trs.g(this.g,t,4,t.bb(),_n.b.eX(),_n.b.eY(),t.A(),null,null);break;default:i=this.k(t);break}return i},k:function(n){this.j&&(this.j=new _trs.g(this.g,n,0,_j.g.a,null,null,"",null,null));return this.j}};_trs.d=function(n,t,i,r){this.q=Function.createDelegate(this,this.E);_trs.d.initializeBase(this,[t,n,null,!1,null,null,"ModuleSwitcherView.ContextMenuSwitch"]);this.i=i;this.m=r;this.z(new _j.g(this.q,_trs.f.a))};_trs.d.prototype={m:null,y:function(){return this.m.b===this.i},C:function(){return String.format(_u.R.SI,this.k)},i:null,e:function(){return new _trs.d(this.p,this.k,this.i,this.m)},bz:function(){this.m=null;_j.S.prototype.bz.call(this)},E:function(){this.m.v(this.i)}};_trs.f=function(n,t,i,r,u,f){this.f=Function.createDelegate(this,this.u);_trs.f.initializeBase(this);_a.b.c(_trs.f.a,"ModSwitchInit");this.o=n;this.j=t;this.c=i;this.d=r;this.e=u;this.r=f;this.t();this.s(this.c.a());this.c.b(this.f);this.g=!t.a().gQ().Enabled};_trs.f.prototype={o:null,j:null,c:null,d:null,e:null,r:null,b:0,q:null,l:null,i:null,m:null,p:null,n:null,g:!1,a:null,h:null,s:function(n){if(this.b!==n){this.b=n;this.eH("CurrentModuleType")}return n},v:function(n){var i=new _a.l;i.b("F",_a.M.toString(this.b));i.b("T",_a.M.toString(n));var t;var u,r;(r=this.w(n,u={val:t}),t=u.val,r)?this.d.c(t):this.o.a(_a.X.a(n),null);_h.h.a(_trs.f.a,"ModSwitch",19,1,i)},eJ:function(){this.c.c(this.f);_a.gd.prototype.eJ.call(this)},w:function(n,t){t.val=null;if(n===5){t.val=this.d.b().replace(this.d.k(),"/mail/photohub.aspx");return!0}return!1},t:function(){this.a=new Array(0);this.l=new _trs.d(_fm.b.a(_fm.a.f),_u.R.DK,0,this);this.a.push(this.l);if(this.e.bH.Calendar){this.i=new _trs.d(_fm.b.a(_fm.a.D),_u.R.Im,1,this);this.a.push(this.i)}if(this.e.bH.Contacts){this.m=new _trs.d(_fm.b.a(_fm.a.K),_u.R.Fc,2,this);this.a.push(this.m)}if(this.j.a().lg().Enabled){this.n=new _trs.d(_fm.b.a(_fm.a.bY),_u.R.Ia,5,this);this.a.push(this.n)}if(this.e.bH.Tasks){this.p=new _trs.d(_fm.b.a(_fm.a.bu),_u.R.FB,3,this);this.a.push(this.p)}this.h=new _trs.d(_fm.b.a(_fm.a.h),_u.R.Py,null,this)},u:function(){this.s(this.c.a())}};_trs.i=function(){_trs.i.initializeBase(this)};_trs.i.prototype={e:null,K:function(n){var i=new _dg.cG(this.L);var t=new _dg.bZ(this.M());n.bB(t,i,this.I,this.H)},cU:function(n,t,i){if(n&&n.AccountInfo){this.e=new _dg.W(n.AccountInfo);t()}}};_trs.e=function(n){this.c=-1;this.a=new _fm.e(null);this.e=new _j.l;_trs.e.initializeBase(this,[n]);this.y("ModuleSwitcherView")};_trs.e.prototype={b:!1,g:function(){if(this.c===-1){this.c=205;this.f()}return this.c},j:function(n){if(this.c!==n){this.c=n;this.b||this.f()}return n},k:function(n){if(this.b!==n){this.b=n;this.b&&this.f();this.by("IsVertical")}return n},h:function(){return!this.a.p.x.length},d:!1,f:function(){this.d=!1;var u=this.V();var i=u.a.length;var n;if(this.b)n=Math.min(5,i);else{var f=Math.floor((this.g()-5)/40);n=Math.min(f,i);n<i&&(n-=1)}this.e.g();this.i();for(var t=0;t<i;t++){var r=u.a[t];if(t<n)this.e.a(r);else{this.a.p.a(r.e());r.i===u.b&&(this.d=!0)}}this.bA("HideMoreModulesButton","IsActiveModuleInOverflowMenu")},i:function(){this.a.q()&&this.a.r.a();for(var t=this.a.p.x.length-1,n=t;n>=0;n--){this.a.p.x[n].dispose();this.a.p.n(n)}}};_trs.a=function(){};_trs.a.$$cctor=function(){};_trs.a.v=function(){var n=window.document.createElement("DIV");n.innerHTML="<div> <button type='button' class='__Microsoft_Owa_TriageShared_templates_cs_3'></button> </div><div>  <div></div> </div><div><div class='__Microsoft_Owa_TriageShared_templates_cs_2'></div></div><div> <div></div> </div><div> <div class='__Microsoft_Owa_TriageShared_templates_cs_6 flex flexwrap'></div>  <button type='button' class='__Microsoft_Owa_TriageShared_templates_cs_c __Microsoft_Owa_TriageShared_templates_cs_7 ms-fcl-tp'></button> </div><div>  <div class='__Microsoft_Owa_TriageShared_templates_cs_4 flex flexwrap ms-bgc-nl'></div> </div><div>  <button type='button' class='__Microsoft_Owa_TriageShared_templates_cs_7 __Microsoft_Owa_TriageShared_templates_cs_d ms-fcl-tp'></button> <div></div> </div><div> <button type='button' class='__Microsoft_Owa_TriageShared_templates_cs_8 __Microsoft_Owa_TriageShared_templates_cs_d ms-font-m ms-fcl-tp ms-bgc-tl-h'></button> </div><div> <a class='__Microsoft_Owa_TriageShared_templates_cs_e ms-bgc-tp ms-fcl-w'></a> <div></div>   </div>";_j.i.a().appendChild(n);return n};_trs.a.N=function(n){return n.e()};_trs.a.K=function(n){return n.c()};_trs.a.M=function(n){return n.d()};_trs.a.L=function(n){return n.h()};_trs.a.P=function(n){return n.g()};_trs.a.J=function(n){return n.bL()};_trs.a.O=function(n){return n.f()};_trs.a.n=function(n){return n.h};_trs.a.g=function(n){return n.k};_trs.a.l=function(n){return n.p};_trs.a.c=function(n){return n.X};_trs.a.Y=function(n){return _trs.e.isInstanceOfType(n)?n.h():null};_trs.a.ba=function(n){return _trs.e.isInstanceOfType(n)?n.d:null};_trs.a.u=function(n){return _trs.e.isInstanceOfType(n)?n.a:null};_trs.a.H=function(n){return n.q()};_trs.a.z=function(n){return n.k()};_trs.a.Z=function(n){return n.e};_trs.a.bb=function(n){return n.b};_trs.a.V=function(n){return n.C()};_trs.a.j=function(n){return n.y()};_trs.a.s=function(n){return n.j};_trs.a.U=function(n){return n.i===1};_trs.a.t=function(n){return n.c()};_trs.a.F=function(n){return n.r};_trs.a.G=function(n){return n.u};_trs.a.X=function(n){return n.g};_trs.a.W=function(n){return n.q};_trs.a.R=function(n){return _n.I.isInstanceOfType(n)?n.a:null};_trs.a.Q=function(n){return n.b};_trs.a.f=function(n,t){n.l(t)};_trs.a.x=function(n,t){n.m(t)};_trs.a.e=function(n,t){n.T(t)};_trs.a.y=function(n,t){n.dQ(t)};_trs.a.w=function(n,t){n.bQ(t)};_trs.a.m=function(n,t){n.bk(t)};_trs.a.r=function(n,t){n.bl(t)};_trs.a.h=function(n,t){n.K(t)};_trs.a.o=function(n,t){n.Q(t)};_trs.a.B=function(n,t){n.b=t};_trs.a.C=function(n,t){n.c(t)};_trs.a.I=function(n,t){n.m(t)};_trs.a.A=function(n,t){n.j(t)};_trs.a.p=function(n,t){n.o(t)};_trs.a.T=function(n,t){n.b=t};_trs.a.S=function(n,t){n.b=t};_trs.a.q=function(n,t){n.k(t)};_trs.a.D=function(n,t){n.u(t)};_trs.a.E=function(n,t){n.b=t};_trs.a.bd=function(n,t){n.k(t)};_trs.a.bc=function(n,t){n.j(t)};_trs.a.k=function(){_trs.a.d||(_trs.a.d=new _fc.k);return _trs.a.d};_trs.a.i=function(){};TriageSharedComponent.registerClass("TriageSharedComponent",null,_a.ki,_j.ce);_trs.d.registerClass("_trs.d",_fm.c);_trs.f.registerClass("_trs.f",_a.bw,_y.gC,_a.kV,_j.bs,Sys.IDisposable);_trs.i.registerClass("_trs.i",_h.fK);_trs.e.registerClass("_trs.e",_j.c);TriageSharedComponent.$$cctor();_trs.b.c=!1;_trs.b.a=new _a.k([3,5,4,1]);_trs.b.b=new _a.k([4,1]);_trs.b.d=new _a.k([3,4,1]);_trs.f.a=_a.a.fe;_trs.a.b=_trs.a.v();_trs.a.d=null;_trs.a.a={};_trs.a.$$cctor();
window.scriptsLoaded['microsoft.owa.triageshared.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.triageshared.js'] = (new Date()).getTime();