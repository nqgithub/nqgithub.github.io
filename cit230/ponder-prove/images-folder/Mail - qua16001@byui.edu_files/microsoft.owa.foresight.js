﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.foresight.js'] = (new Date()).getTime();
Type.registerNamespace("_for");_for.n=function(){};function ForesightComponent(){}ForesightComponent.$$cctor=function(){_a.t.a().a(ForesightComponent)};ForesightComponent.prototype={b:function(n,t,i){var r=this;n.b(_y.gM,function(){return new _for.b(new _for.k(new(_h.dW.$$(_for.i))(_g.b.a.nameToId("calendar"))),n.a(_a.S),n.d(_cc.bI),n.a(_cc.K),n.a(_g.h),n.a(_a.q))}).a()},a:function(){return null}};_for.i=function(n,t){_for.i.initializeBase(this,[n,[t],null])};_for.i.prototype={bD:function(){return _a.a.p},bM:function(n){return _a.m.e(_dg.a,null,n)},bN:function(n,t){var r=_a.d.a().d();var u=r.l(1);var e=r.c(2);var f=new _h.m(u,e);var i=new _cc.bz(200);i.bj=10;i.bg=_g.b.a.nameToId("calendar");i.be=f;i.bi=new _j.l;return i},bR:function(n){var t=n;return new _h.cp(t.N.Body.Items)},cb:function(n){this.k(null,null,null)}};_for.k=function(n){this.b=n};_for.k.prototype={b:null,a:function(){return new _for.i(this.b,new _h.eJ(!0))}};_for.e=function(){};_for.e.a=function(n){var t=_a.d.a();return!n.g()&&n.a().a(t)<=0&&n.b().a(t)>=0};_for.e.b=function(n,t){return n.a().a(t)>0};_for.e.c=function(n,t){return!!t&&!n.a().a(t)};_for.e.d=function(n,t){return n.g()&&n.a().k(t)<=0};_for.d=function(n,t,i){this.s=Function.createDelegate(this,this.D);this.y=Function.createDelegate(this,this.T);this.A=Function.createDelegate(this,this.U);this.C=Function.createDelegate(this,this.M);this.z=Function.createDelegate(this,this.G);this.B=Function.createDelegate(this,this.H);this.t=Function.createDelegate(this,this.V);this.x=Function.createDelegate(this,this.N);_for.d.initializeBase(this);this.w=n;this.u=new _j.g(this.x,_for.b.a);this.b=new _j.l;this.e=t;this.e.be(this.t);this.m=i;this.v=new _j.g(this.B,_for.b.a)};_for.d.a=function(n){return n.p()};_for.d.b=function(n){return n.bH.ItemId.Id};_for.d.prototype={g:!1,n:null,i:0,o:null,d:null,f:!1,w:null,e:null,b:null,m:null,u:null,l:null,j:null,h:function(){return!!this.e&&this.f},p:function(){return 460},q:function(){return 352},c:function(){return this.f},a:function(n){if(this.f!==n){this.f=n;this.eH("IsShown")}return n},E:function(){return this.b.c(this.i)},K:function(n){if(this.n!==n){this.n=n;this.eH("FirstNextEventStartTime")}return n},Q:function(){return this.b.b()>0},r:function(n){if(this.d!==n){this.d=n;this.D(null,null);this.eH("SelectedItem")}return n},v:null,P:function(){this.o||this.O();return this.o},L:function(n){if(this.i!==n){this.i=n;this.eH("ItemToScrollTo")}return n},bT:function(n){return n},bs:function(n){return n},bS:function(n){this.f&&n.dispose()},dy:function(n){return""},G:function(){this.a(!1);this.r(null)},M:function(n){this.I();this.a(!0);if(n){this.r(n);this.H()}else this.Q()&&!this.g?this.l.a():this.E()&&this.j.a();_a.b.c(_for.b.a,"UpNextShowAgenda")},eJ:function(){this.r(null);var n;_a.h.a(n={val:this.b}),this.b=n.val;this.e.bo(this.t);this.e=null;_a.gd.prototype.eJ.call(this)},R:function(){for(var t=new Array(0),n=0,r=this.e.bx.x.length;n<r;n++){if(t.length>=20)break;var i=this.e.bx.x[n];t.push(i)}return t},U:function(n,t){if(n){n.N(t.bH);return n}else return new _for.j(t,this.m,this.z,this.C)},S:function(){_h.R.a(this.b,this.R(),_for.d.a,_for.d.b,this.A,!0,!1,_for.b.a)},V:function(n,t){if(!this.e.d()){this.S();this.f&&this.I()}},N:function(){this.G();_a.b.c(_for.b.a,"UpNextNavToCal");this.w.a(_a.X.a(1),null)},O:function(){var t=_a.d.a();var n=new _y.cp;this.o=new _y.bk(n,this.y,t,null,!1);this.eH("GroupGenerator")},T:function(n){var t=_a.d.a().d();return _for.e.d(n.b,t)?t:n.b.a()},I:function(){this.L(-1);this.g=!1;this.K(null);for(var u=_a.d.a(),r=this.b,t=0;t<r.b();t++){var n=r.c(t).b;if(!this.g&&!n.g()){var f=_for.e.a(n);var i=_for.e.b(n,u);if(i||f&&this.i===-1){this.L(t);this.g=i;this.K(i?n.a():null)}}}this.eH("AreNoFutureEventsInRange")},H:function(){this.d.n.a()},D:function(n,t){this.d&&(this.d.a?this.d.rpcl("CalendarItemPeekViewModel",this.s):this.d.apcl("CalendarItemPeekViewModel",this.s))}};_for.l=function(n,t){this.B=Function.createDelegate(this,this.G);this.e=Function.createDelegate(this,this.U);this.s=Function.createDelegate(this,this.X);_for.l.initializeBase(this,[null,t,null,null]);this.c=n;this.c.be(this.s)};_for.l.prototype={l:null,h:null,c:null,g:0,f:null,E:function(n){if(this.g!==n){this.g=n;this.eH("ConflictingMeetingsCount")}return n},R:function(){return this.S()},Q:function(){return this.b.bH.IsAllDayEvent?!1:this.C()<=5},j:function(){return!!this.b},T:function(){var r=_a.d.a();this.f=null;var i=new _dg.a;this.E(0);for(var t=0,u=this.c.bx.x.length;t<u;t++){var n=this.c.bx.x[t];if(n.bH.IsAllDayEvent&&this.c.bx.x.length===1||!n.bH.IsAllDayEvent&&!this.V(n,r))if(this.f)if(this.f.C(n.a()))this.E(this.g+1);else return i;else{this.f=n.a();i=n}}return this.f?i:null},eJ:function(){this.c&&this.c.bo(this.s);_for.j.prototype.eJ.call(this)},O:function(){if(this.j()){var f=_a.d.a();var u=this.f;var i=u.e(f);var t=i>36e5?18e5:6e4;var n=i%t;return n>0?n:t}else return 36e5},Y:function(){var n=this.T();n&&this.p()===n.bH.ItemId.Id?this.N(n.bH):this.A(n)},z:function(){this.eP(["NextMeetingName","NextMeetingLocation","NextMeetingTimeString","HighlightMeetingTime"]);_for.j.prototype.z.call(this)},y:function(){if(this.b){var n=this.b;n.rpcl("Subject",this.e);n.rpcl("Location",this.e);n.rpcl("Start",this.e)}_for.j.prototype.y.call(this)},x:function(){if(this.b){var n=this.b;n.apcl("Subject",this.e);n.apcl("Location",this.e);n.apcl("Start",this.e)}_for.j.prototype.x.call(this)},i:function(){this.I()!==this.p()&&this.r(null);_for.j.prototype.i.call(this)},K:function(){this.i()},U:function(n,t){switch(t){case"Subject":this.eH("NextMeetingName");break;case"Location":this.eH("NextMeetingLocation");break;case"Start":this.eL("NextMeetingTimeString","HighlightMeetingTime");break;default:return}},D:function(){var n=_a.d.a();return new _a.d(n.g(),n.f(),n.j(),n.m(),n.q(),0,0,0)},S:function(){var r=this.b;var e=this.D();var t=r.a();var n=this.C();var i=t.b(0);if(r.bH.IsAllDayEvent){var o=_a.d.a().d();return t.l(1).k(o)<=0?_u.R.It:_u.R.W}else if(t.j()!==e.j())return String.format(_u.n.Tl,i);else if(n>=60)return String.format(_u.n.Ud,i);else if(n<=0)return _u.n.Kr;else{var u=_a.bH.b(n,_a.v.b(),!0);var f=n+" "+u;return String.format(_u.n.QN,f)}},C:function(){var n=this.D();return Math.floor(this.b.a().e(n)/6e4)},V:function(n,t){var i=n.a().e(t)/6e4;return i<-5},X:function(n,t){if(!this.c.d()){this.h&&(this.h=_j.m.a().b(this.h));this.G()}},G:function(){this.Y();this.eH("ConflictingMeetingsCount");if(!this.j()&&this.c.bx.x.length>0&&(!this.l||_a.d.a().e(this.l)>=36e5))this.W();else{var n=this.O();this.h=this.P(n)}},P:function(n){return _j.m.a().a(_for.b.a,"UpNextUpdate",this.B,n)},W:function(){this.l=_a.d.a();this.c.k(null,200,null)}};_for.j=function(n,t,i,r){this.m=Function.createDelegate(this,this.be);this.u=Function.createDelegate(this,this.bf);this.v=Function.createDelegate(this,this.K);this.w=Function.createDelegate(this,this.L);this.t=Function.createDelegate(this,this.bd);this.H=Function.createDelegate(this,this.i);_for.j.initializeBase(this);this.A(n);this.d=t;this.n=new _j.g(this.H,_for.b.a);this.o=i;this.q=r};_for.j.prototype={q:null,o:null,a:null,b:null,A:function(n){if(this.b!==n){this.y();this.b=n;this.eH("CalendarItem");this.x()}return n},n:null,d:null,bb:function(){var n=this.b.bH.Subject;return _j.h.b(n)?_u.R.VE:n},ba:function(){return this.b.bw()},bc:function(){return this.b.a().b(0)},r:function(n){if(this.a!==n){this.bh();this.a&&this.a.dispose();this.a=n;this.eH("CalendarItemPeekViewModel");this.bg()}return n},Z:function(){return this.a?this.a.c():!1},p:function(){return this.b?this.b.bH.ItemId.Id:null},I:function(){return this.a?this.a.b().b.bH.ItemId.Id:null},N:function(n){this.b.dO(n);this.z()},z:function(){if(this.a){var n=this.a.c()&&this.I()===this.p();this.a.a(!1);this.r(this.d.A(this.b));n&&this.i()}},bh:function(){if(this.a){this.a.rpcl("IsShown",this.t);this.a.rpcl("IsFullItemLoaded",this.w);this.a.b().i.cG(this.v);this.a.j(this.u)}},bg:function(){if(this.a){this.a.apcl("IsShown",this.t);this.a.g(this.u);this.a.e()?this.L(this,"IsFullItemLoaded"):this.a.apcl("IsFullItemLoaded",this.w)}},y:function(){},x:function(){},eJ:function(){this.A(null);this.r(null);this.d.rpcl("IsReadyToCreateCalendarItemPeekViewModels",this.m);this.d=null;_a.gd.prototype.eJ.call(this)},i:function(){this.d.L()?this.M():this.d.apcl("IsReadyToCreateCalendarItemPeekViewModels",this.m)},K:function(){this.q&&this.q(this)},bf:function(){this.o&&this.o()},L:function(n,t){this.a.b().i.bz(this.v)},M:function(){this.a||this.r(this.d.A(this.b));this.a.a(!0)},bd:function(n,t){this.eH("HasPeekShowing")},be:function(n,t){this.d.rpcl("IsReadyToCreateCalendarItemPeekViewModels",this.m);this.M()}};_for.b=function(n,t,i,r,u,f){this.r=Function.createDelegate(this,this.S);this.q=Function.createDelegate(this,this.P);this.p=Function.createDelegate(this,this.O);this.z=Function.createDelegate(this,this.R);_for.b.initializeBase(this);this.x=n;this.d=this.x.a();this.y=t;this.u=i;this.v=r;this.j=u;this.t=f;this.g=(262144&this.j.a().v())!=262144};_for.b.prototype={j:null,t:null,x:null,o:!0,g:!1,l:null,m:null,e:null,f:null,i:0,y:null,u:null,h:!1,n:null,v:null,b:function(){return"IsReady"},K:function(){return this.B()||this.C()||this.w()||this.H()},L:function(){this.h||this.N();return this.h},Q:function(n){if(this.h!==n){this.h=n;this.eH("IsReadyToCreateCalendarItemPeekViewModels")}return n},s:null,D:function(n){if(this.l!==n){this.l=n;this.eH("AgendaButtonLabelText")}return n},E:function(n){if(this.m!==n){this.m=n;this.eH("AgendaButtonTooltipText")}return n},I:function(){if(this.B())return _u.R.Vl;else if(this.C())return _u.n.BR;return this.w()?_u.n.OH:_u.n.GI},d:null,B:function(){return this.o&&this.d.d()},C:function(){return this.d.bU&&this.w()},w:function(){return!this.d.bx.x.length},H:function(){return!!this.e&&!this.e.j()},a:function(n){if(n!==this.i){this.i=n;this.eH("IsReadingPaneOff");this.G()}},c:function(){_h.g.a().f(this.d);this.f=new _for.d(this.y,this.d,this);this.s=new _j.g(this.z,_a.a.p);this.e=new _for.l(this.d,this);this.e.apcl("ConflictingMeetingsCount",this.p);this.e.apcl("CalendarItem",this.q);this.d.k(null,200,null);this.d.be(this.r)},A:function(n){return n?this.n.a(this.v.a(n)):null},eJ:function(){var t;_a.h.a(t={val:this.f}),this.f=t.val;this.e.rpcl("ConflictingMeetingsCount",this.p);this.e.rpcl("CalendarItem",this.q);var n;_a.h.a(n={val:this.e}),this.e=n.val;if(this.d){this.d.bo(this.r);_h.g.a().b(this.d)}_a.gd.prototype.eJ.call(this)},N:function(){var n=this;this.u.a(function(t){n.n=t;n.Q(!!n.n)})},M:function(){this.g=!0;var n;(n=this.j.a()).x(n.v()&-262145);_h.f.a(this.j.a().u,this.t)},G:function(){var n=this.e?this.e.g:0;if(n>0){this.D(String.format(_u.n.It,n));this.E(n===1?_u.n.Qd:String.format(_u.n.PG,n))}else{this.D(this.i===1&&this.g?"":_u.n.UD);this.E(_u.n.Ga)}},R:function(){this.g||this.M();this.f.M(null)},S:function(n,t){if(!this.d.d()){if(this.o){this.eH("IsReady");this.o=!1;var u=this.d.bx.x.length;var i=Math.floor(u/5);u%5>0&&i++;i=Math.min(i,5);var r=new _a.l;r.a("B",i);r.a("E",u);_a.b.c(_for.b.a,"UpNextInitEC",r.toString(),0)}this.eL("IsEmptyScenario","EmptyScenarioLabelText")}},P:function(n,t){this.eH("NextMeetingItemViewModel")},O:function(n,t){this.G()}};_for.c=function(){};_for.c.b=function(){return _fm.b.a(_fm.a.j,_fm.WebfontSizes.a.f)};_for.c.a=function(){return _fm.b.a(_fm.a.j,_fm.WebfontSizes.a.b)};_for.c.e=function(){return _fm.b.a(_fm.a.J,_fm.WebfontSizes.a.b,"ms-fcl-tp-b")};_for.c.f=function(){return _fm.b.a(_fm.a.N,_fm.WebfontSizes.a.a,"ms-fcl-ns-b")};_for.c.c=function(){return _fm.b.a(_fm.a.bU,_fm.WebfontSizes.a.a,"ms-fcl-ns-b")};_for.c.d=function(){return _fm.b.a(_fm.a.T,_fm.WebfontSizes.a.a,"ms-fcl-ns-b")};_for.c.h=function(){return _fm.b.a(_fm.a.J,_fm.WebfontSizes.a.a,"ms-fcl-w-b")};_for.c.g=function(){return _fm.b.a(_fm.a.cm,_fm.WebfontSizes.a.a,"ms-fcl-w-b")};_for.h=function(n,t){this.d=Function.createDelegate(this,this.e);_for.h.initializeBase(this,[n,t])};_for.h.prototype={b:null,a:null,c:null,f:function(n){if(!this.a){this.a=new _j.g(this.d,this.I());this.by("JumpToItemToScrollToCommand")}return n},g:function(n){if(!this.b){this.b=new _j.g(this.mu,this.I());this.by("JumpToNoUpcomingCommand")}return n},H:function(){_fce.a.prototype.H.call(this);this.c=this.V()},e:function(){var t=this.bP(this.c.E());var n=this.x().c(t);this.fE(n)&&this.cH(n)}};_for.g=function(n,t,i,r){_for.g.initializeBase(this,[n]);this.m=t;this.j=i;this.g=r};_for.g.prototype={d:null,i:null,b:null,a:null,g:null,k:null,n:null,m:null,j:null,l:function(){return this.a.g()},p:function(){return _for.e.c(this.a,this.w().n)},q:function(){return _for.e.a(this.a)},o:function(){return this.a.l()},h:function(){return this.a.e()},r:function(){return this.a.fc()},H:function(){_fce.e.prototype.H.call(this);if(this.B){this.b=this.B.a("Event");this.n=this.b.z;this.a=this.V().b;this.k=this.a.a().d();this.d=this.B.a("calendarFreeBusyView");this.i=this.B.a("contentDiv");this.E();this.bi()}},bz:function(){this.a=null;_fce.e.prototype.bz.call(this)},s:function(){if(this.l()||this.a.bH.IsAllDayEvent)return this.b.z;_j.B.b(this.z.children,"background-color","");return null},E:function(){var t=this.s();if(t){var i=this.a.e()?this.a.e().f:-1;t.style.backgroundColor=this.g.b(i,2)}var n=this.b.z;n&&(n.style.opacity=this.a.gX()?"0.6":"")},bi:function(){this.d&&this.h()&&this.d.n(this.h().f,this.h().e(),this.r(),this.o(),100,!1)}};_for.m=function(){};_for.m.prototype={a:function(n,t){var r=n;var e=r.bH.IsAllDayEvent;var o=r.a();var i=r.b();var u=i.l(1);e&&u.C(i.c(1).d())&&(i=u);var f=Math.floor((i.h()-o.h())/1e3);return _a.d.z(f,!1)},b:function(n,t){return null}};_for.f=function(n,t,i,r,u){this.h=Function.createDelegate(this,this.u);_for.f.initializeBase(this,[n]);this.l=t;this.k=i;this.e=r.a().gM().Enabled;this.y("AgendaContextPeekListItemView.CharmsContainer");this.j=u};_for.f.prototype={l:null,k:null,e:!1,j:null,d:null,a:null,c:null,g:null,f:!1,i:!1,s:function(){return this.a.b().l(-1).a(this.c)>=0&&!this.a.a().k(this.c)},r:function(){return this.a.a().a(this.c)<=0&&!this.a.b().l(-1).k(this.c)},t:function(){var n=this.a;return n.dy()?_for.c.f():n.dN()?_for.c.c():null},m:function(n){if(this.a!==n){this.a&&this.a.rpcl("Location",this.h);this.a=n;this.a&&this.f&&this.a.apcl("Location",this.h)}return n},H:function(){_j.c.prototype.H.call(this);if(this.B){this.m(this.V());this.d=this.B.a("charmsContainer");if(this.V()){this.c=this.a.a().d();this.n()}}},Y:function(){_j.i.prototype.Y.call(this);this.m(this.V());if(this.V()&&this.d){this.c=this.a.a().d();this.n()}},bz:function(){this.m(null);_j.c.prototype.bz.call(this)},n:function(){if(this.e&&!this.g){var n=this;this.j.a(function(t){n.g=t;n.o()})}else this.o()},o:function(){_j.k.w(this.d.z);(this.i||this.e)&&this.p();var n=this.f&&!_j.h.b(this.a.A().bH.DisplayName);if(this.e){this.a.et()==="None"&&this.q();n=n&&!this.d.z.children.length}n&&this.b(_n.b.X())},q:function(){var n=this.g.a([this.a.bH.Subject,this.a.bH.Preview],null);n&&this.b(n)},p:function(){var n=this.a;n.ce()&&this.b(this.t());var t=n.et()!=="None"&&!n.dN()&&_cc.a.b==="Mouse";var i=n.ce()&&n.bH.HasAttachments&&n.cG()&&t;!i&&n.bH.HasAttachments&&this.b(_n.b.g());n.cG()&&this.b(_for.c.d());t&&this.b(_cc.P.a.a(this.a.et(),null));if(n.g()){this.s()||this.b(_for.c.g());this.r()||this.b(_for.c.h())}},b:function(n){var t=new _fc.d(document.createElement("span"),this.l,this.k);t.a(n);this.d.z.appendChild(t.z);t.bn()},u:function(n,t){this.n()}};_for.a=function(){};_for.a.$$cctor=function(){_for.a._I()};_for.a.K=function(){var n=window.document.createElement("DIV");n.innerHTML="<div>  <div></div> <span class='_for_6 ms-font-s ms-fwt-sl ms-bgc-tlr ms-bcl-nta'></span> </div><div> <span class='_for_3 ms-font-m ms-fwt-sl ms-fcl-np ms-bgc-nlr'></span> </div><div><div></div></div><div> <div class='_for_2'> <div class='_for_5 ms-bcl-nta'> <div class='hiddenOverflow'></div> </div> <button type='button' class='_for_4 ms-font-s ms-fcl-tp ms-fcl-td-h ms-fwt-sb'></button> </div>  </div><div> <div class='flex flexCenterItems'></div> </div><div> <div class='outerContainer'>  <div autoid=\"_for_0\" class='_for_a eventMarginHeight ms-bgc-tlr'> <div class='_for_b'></div> <span class='_for_e'></span> <span class='_for_h _for_c ms-fwt-r ms-fcl-tp'></span> <span class='_for_h _for_d ms-font-s ms-fwt-r ms-bgc-tp ms-fcl-w'></span> <div class='_for_f'> <span class='_for_h _for_i ms-fwt-r'></span> <div class='_for_h _for_j'> <span class='_for_l ms-fwt-sl bidiEmbed'></span> <span class='_for_k ms-fwt-sl bidiEmbed bidi'></span> </div> <div class='_for_g'></div> </div> </div> </div>  </div><div> <div class='flex flexCenterItems _for_p ms-bgc-tl'> <span class='_for_q flex1 flexCenterItems flex'> <span class='ms-font-s ms-fcl-tp ms-fwt-sb'></span> <span class='_for_w ms-font-s ms-fwt-r'></span> <div class='_for_v'></div> <span class='_for_z ms-font-s ms-fcl-ns'></span>  </span> <div class='_for_q flex1 flex flexCenterItems'> <span class='ms-font-s ms-fcl-tp ms-fwt-sb'></span> <span class='_for_w ms-font-s ms-fwt-r'></span> </div> <div class='_for_r flex flexCenterItems ms-bgc-tl'> <span class='_for_u ms-font-s ms-fcl-ns'>  </span> <span class='_for_t flex flexCenterItems ms-font-s ms-fcl-tp ms-fcl-td-h ms-fwt-sb'> <span></span> <span class='_for_x'></span>  </span> </div> </div> </div>";_j.i.a().appendChild(n);return n};_for.a.bj=function(n){return n.m};_for.a.F=function(n){return n.I()};_for.a.ba=function(n){return n.g};_for.a.Y=function(n){return n.h()};_for.a.Z=function(n){return n.b};_for.a.bg=function(n){return n};_for.a.bc=function(n){return n.P()};_for.a.bi=function(n){return n.d};_for.a.O=function(n){return n.E()};_for.a.bf=function(n){return n.l};_for.a.bx=function(n){return n.b};_for.a.be=function(n){return n.j};_for.a.bw=function(n){return n.a};_for.a.bh=function(n){return n.v};_for.a.bb=function(n){return n.u};_for.a.G=function(n){return n.l()};_for.a.k=function(n){return n.a};_for.a.A=function(n){return n.c()};_for.a.o=function(n){return n.b()};_for.a.m=function(n){return n.z};_for.a.r=function(n){return n.Z()};_for.a.H=function(n){return n.q()};_for.a.bq=function(n){return n.bc()};_for.a.bv=function(n){return n.p()};_for.a.D=function(n){return n.bb()};_for.a.q=function(n){return n.b};_for.a.s=function(n){return n.ba()};_for.a.b=function(n){return n.e};_for.a.bu=function(n){return!n.i};_for.a.C=function(n){return n.j()};_for.a.l=function(n){return n.n};_for.a.bt=function(n){return n.K()};_for.a.bp=function(n){return n.R()};_for.a.bo=function(n){return n.Q()};_for.a.bs=function(n){return n.m};_for.a.t=function(n){return n.s};_for.a.E=function(n){return n.f};_for.a.bd=function(n){return n.f};_for.a.br=function(n){return n.l};_for.a.c=function(n,t){n.a(t)};_for.a.f=function(n,t){n.K(t)};_for.a.Q=function(n,t){n.bl(t)};_for.a.P=function(n,t){n.dn(t)};_for.a.R=function(n,t){n.df(t)};_for.a.bn=function(n,t){n.r(t)};_for.a.T=function(n,t){n.bg(t)};_for.a.bm=function(n,t){n.l=t};_for.a.bz=function(n,t){n.g(t)};_for.a.bl=function(n,t){n.j=t};_for.a.by=function(n,t){n.f(t)};_for.a.S=function(n,t){n.cm=t};_for.a.M=function(n,t){n.l(t)};_for.a.N=function(n,t){n.k(t)};_for.a.L=function(n,t){n.T(t)};_for.a.x=function(n,t){n.i(t)};_for.a.z=function(n,t){n.f(t)};_for.a.B=function(n,t){n.a(t)};_for.a.p=function(n,t){n.a(t)};_for.a.w=function(n,t){n.G=t};_for.a.y=function(n,t){n.c(t)};_for.a.u=function(n,t){n.a(t)};_for.a.v=function(n,t){n.ba(t)};_for.a.n=function(n,t){n.T(t)};_for.a.j=function(n,t){n.l=t};_for.a.U=function(n,t){n.bk(t)};_for.a.V=function(n,t){n.i(t)};_for.a.X=function(n,t){n.f(t)};_for.a.bk=function(n,t){n.a(t)};_for.a.W=function(n,t){n.c(t)};_for.a.e=function(){_for.a.g||(_for.a.g=new _fc.k);return _for.a.g};_for.a.J=function(){_for.a.i||(_for.a.i=new _for.m);return _for.a.i};_for.a.I=function(){_for.a.h||(_for.a.h=new _fc.l);return _for.a.h};_for.a._I=function(){var r="AgendaContextPeekView._tid1";new _j.d(r,function(){_for.a.a[r]===undefined&&(_for.a.a[r]=[null,[[-1,0,["UpNextViewModel","EmptyScenarioLabelText"],[_for.a.bj,_for.a.F],null,"Text",null,_for.a.c,1,null,null,null],[-1,0,["AreNoFutureEventsInRange"],[_for.a.ba],null,"IsHidden",null,_for.a.f,1,null,null,!0]]]);var n=_for.a.d.childNodes[0].cloneNode(!0);var i=new _fc.a(n.children[1]);var t=new _fce.d(n.children[0]);return new _j.a(n,[t,i]).l({ListPanel:t})},"",_for.d,_for.h,function(n){return new _for.h(n,_j.b.Instance.a(_ff.a))},!1,!0,!1,0,_for.a.a);var u="AgendaContextPeekView.GroupHeaderTemplate";new _j.d(u,function(){_for.a.a[u]===undefined&&(_for.a.a[u]=[[[-1,0,["Text"],[_for.a.Y],null,"Text",null,_for.a.c,1,null,null,null]]]);var n=_for.a.d.childNodes[1].cloneNode(!0);var t=new _fc.a(n.children[0]);return new _j.a(n,[t])},"",_y.M,_j.c,function(n){return new _j.c(n)},!1,!1,!1,0,_for.a.a);var f="AgendaContextPeekView";new _j.d(f,function(){_for.a.a[f]===undefined&&(_for.a.a[f]=[null,[[-1,0,["AgendaMeetingsToDisplay"],[_for.a.Z],null,"DataSource",null,_for.a.Q,1,null,null,null],[-1,0,["ListViewItemDataConverter"],[_for.a.bg],null,"DataConverter",null,_for.a.P,1,null,null,null],[-1,0,["GroupGenerator"],[_for.a.bc],null,"GroupGenerator",null,_for.a.R,1,null,null,null],[-1,0,["SelectedItem"],[_for.a.bi],_for.a.bn,"SelectedItem",_for.a.O,_for.a.T,2,null,null,null],[-1,0,["JumpToNoUpcomingCommand"],[_for.a.bf],_for.a.bm,"JumpToNoUpcomingCommand",_for.a.bx,_for.a.bz,2,null,null,null],[-1,0,["JumpToItemToScrollToCommand"],[_for.a.be],_for.a.bl,"JumpToItemToScrollToCommand",_for.a.bw,_for.a.by,2,null,null,null],[-1,0,["OnListViewItemClickCommand"],[_for.a.bh],null,"OnItemClickCommand",null,_for.a.S,0,null,null,null]],[[-1,4,null,null,null,"ImageId",null,_for.a.M,0,null,null,null,_for.c.b()],[-1,4,null,null,null,"Text",null,_for.a.N,0,null,null,null,_u.n.JU],[-1,0,["ClosePeekAndGoToCalendarCommand"],[_for.a.bb],null,"ClickCommand",null,_for.a.L,1,null,null,null]]]);var t=_for.a.d.childNodes[3].cloneNode(!0);var r=new _fc.b(_j.a.a(t,[0,1]));var n=new _for.h(_j.a.a(t,[0,0,0]),_j.b.Instance.a(_ff.a));n.ch("AgendaContextPeekView.GroupHeaderTemplate");n.bZ(!0);n.bc(function(){var t=_for.a.d.childNodes[2].cloneNode(!0).childNodes[0];var n=new _for.g(t,_j.b.Instance.a(_y.a),_j.b.Instance.a(_ff.b),_j.b.Instance.a(_cc.c));n.y("AgendaContextPeekListItemView");return n});n.y("AgendaContextPeekView._tid1");var i=new _fce.g(_j.a.a(t,[0,0]),_j.b.Instance.a(_j.p),_j.b.Instance.a(_ff.a),_j.b.Instance.a(_j.j));return new _j.a(t,[i,n,r])},"",_for.d,_j.c,function(n){return new _j.c(n)},!1,!1,!1,0,_for.a.a);var n="AgendaContextPeekListItemView.CharmsContainer";new _j.d(n,function(){_for.a.a[n]===undefined&&(_for.a.a[n]=[null]);var i=_for.a.d.childNodes[4].cloneNode(!0);var t=new _j.i(i.children[0]);return new _j.a(i,[t]).l({charmsContainer:t})},"",_dg.a,_for.f,function(n){return new _for.f(n,_j.b.Instance.a(_y.a),_j.b.Instance.a(_ff.b),_j.b.Instance.a(_a.e),_j.b.Instance.a(_j.cd.$$(_h.V)))},!1,!1,!1,0,_for.a.a);var t="AgendaContextPeekListItemView";new _j.d(t,function(){_for.a.a[t]===undefined&&(_for.a.a[t]=[[[-1,5,["IsMultidayEvent"],[_for.a.G],null,"_for_o",null,null,1,null,null,null]],[[-1,5,["HasPeekShowing"],[_for.a.r],null,"_for_m ms-bcl-ts:_for_n ms-bcl-nta ms-bgc-w",null,null,0,null,null,null]],null,[[-1,4,null,null,null,"Id",null,_for.a.u,0,null,null,null,_for.c.e()],[-1,1,["IsNowEvent"],[_for.a.H],null,"IsHidden",null,_for.a.f,1,_for.a.e(),null,!0]],[[-1,1,["IsMultidayEvent"],[_for.a.G],null,"IsHidden",null,_for.a.f,1,null,null,!0],[-1,0,["StartTime"],[_for.a.bq],null,"Text",null,_for.a.c,1,null,null,null],[-1,5,["IsNowEvent"],[_for.a.H],null,"ms-fcl-np",null,null,1,_for.a.e(),null,null]],[[-1,4,null,null,null,"Text",null,_for.a.c,0,null,null,null,_u.n.QH],[-1,1,["IsNextEvent"],[_for.a.bv],null,"IsHidden",null,_for.a.f,1,_for.a.e(),null,!0]],null,[[-1,0,["NextMeetingName"],[_for.a.D],null,"Text",null,_for.a.c,1,null,null,null]],[[-1,0,["CalendarItem"],[_for.a.q],null,"Text",null,_for.a.c,1,_for.a.J(),null,null]],[[-1,0,["NextMeetingLocation"],[_for.a.s],null,"Text",null,_for.a.c,1,null,null,null]],[[-1,0,["CalendarItem"],[_for.a.q],null,"DataContext",null,_for.a.v,1,null,null,null]]]);var n=_for.a.d.childNodes[5].cloneNode(!0);var f=new _for.f(_j.a.a(n,[0,0,4,2]),_j.b.Instance.a(_y.a),_j.b.Instance.a(_ff.b),_j.b.Instance.a(_a.e),_j.b.Instance.a(_j.cd.$$(_h.V)));f.i=!0;var l=new _fc.a(_j.a.a(n,[0,0,4,1,1]));var c=new _fc.a(_j.a.a(n,[0,0,4,1,0]));var v=new _fc.a(_j.a.a(n,[0,0,4,0]));var u=new _j.i(_j.a.a(n,[0,0,4]));var s=new _fc.a(_j.a.a(n,[0,0,3]));var a=new _fc.a(_j.a.a(n,[0,0,2]));var h=new _fc.d(_j.a.a(n,[0,0,1]),_j.b.Instance.a(_ff.a),_j.b.Instance.a(_ff.b));var o=new _cc.m(_j.a.a(n,[0,0,0]),_j.b.Instance.a(_dg.h),_j.b.Instance.a(_cc.c),_j.b.Instance.a(_h.e));var e=new _j.i(_j.a.a(n,[0,0]));var r=new _j.i(n.children[0]);var i=new _ck.f(_j.b.Instance.a(_b.f),_j.b.Instance.a(_b.a),_j.b.Instance.a(_y.a),_j.b.Instance.a(_j.j),_j.b.Instance.a(_ff.b));i.U(_j.f.b(2,null,null,null,"ActivationMode",null,_for.a.x,0,null,null,0)).U(_j.f.a(["CalendarItemPeekViewModel"],[_for.a.k],null,"PeekDataContext",null,_for.a.z,1)).U(_j.f.a(["CalendarItemPeekViewModel","IsShown"],[_for.a.k,_for.a.A],_for.a.B,"IsShown",_for.a.o,_for.a.p,2,null,null,!1)).U(_j.f.b(3,null,null,null,"ActionSource",null,_for.a.w,0,null,null,0)).W(_j.f.a(["DOMElement"],[_for.a.m],null,"AnchorElement",null,_for.a.y,1));i.K=!1;i.e("CalendarItemPeekView");r.C([i]);return new _j.a(n,[r,e,o,h,a,s,u,v,c,l,f]).l({MainItemContainer:r,Event:e,calendarFreeBusyView:o,contentDiv:u})},"",_for.j,_for.g,function(n){return new _for.g(n,_j.b.Instance.a(_y.a),_j.b.Instance.a(_ff.b),_j.b.Instance.a(_cc.c))},!1,!1,!1,0,_for.a.a);var i="UpNextView";new _j.d(i,function(){_for.a.a[i]===undefined&&(_for.a.a[i]=[[[-1,5,["NextMeetingItemViewModel","HasPeekShowing"],[_for.a.b,_for.a.r],null,"ms-bgc-w",null,null,0,_for.a.e(),null,null],[-1,5,["IsReadingPaneOff"],[_for.a.bu],null,"_for_s",null,null,0,null,null,null]],[[-1,0,["NextMeetingItemViewModel","HasMeetingToShow"],[_for.a.b,_for.a.C],null,"IsHidden",null,_for.a.f,1,_for.a.e(),null,!0],[-1,0,["NextMeetingItemViewModel","OpenCalendarItemPeekCommand"],[_for.a.b,_for.a.l],null,"ClickCommand",null,_for.a.n,1,null,null,null]],[[-1,4,null,null,null,"Text",null,_for.a.c,0,null,null,null,_u.R.CA]],[[-1,0,["NextMeetingItemViewModel","NextMeetingName"],[_for.a.b,_for.a.D],null,"Text",null,_for.a.c,1,null,null,null],[-1,5,["NextMeetingItemViewModel","NextMeetingLocation"],[_for.a.b,_for.a.s],null,"_for_y",null,null,0,_for.a.I(),null,null]],[[-1,0,["NextMeetingItemViewModel","CalendarItem"],[_for.a.b,_for.a.q],null,"DataContext",null,_for.a.v,1,null,null,null]],[[-1,0,["NextMeetingItemViewModel","NextMeetingLocation"],[_for.a.b,_for.a.s],null,"Text",null,_for.a.c,1,null,null,null]],[[-1,0,["IsEmptyScenario"],[_for.a.bt],null,"IsHidden",null,_for.a.f,1,_for.a.e(),null,!0]],[[-1,4,null,null,null,"Text",null,_for.a.c,0,null,null,null,_u.R.CA]],[[-1,0,["EmptyScenarioLabelText"],[_for.a.F],null,"Text",null,_for.a.c,1,null,null,null]],[[-1,5,["NextMeetingItemViewModel","HasPeekShowing"],[_for.a.b,_for.a.r],null,"ms-bgc-w",null,null,0,_for.a.e(),null,null]],[[-1,0,["NextMeetingItemViewModel","HasMeetingToShow"],[_for.a.b,_for.a.C],null,"IsHidden",null,_for.a.f,1,_for.a.e(),null,!0],[-1,0,["NextMeetingItemViewModel","NextMeetingTimeString"],[_for.a.b,_for.a.bp],null,"Text",null,_for.a.c,1,null,null,null],[-1,0,["NextMeetingItemViewModel","OpenCalendarItemPeekCommand"],[_for.a.b,_for.a.l],null,"ClickCommand",null,_for.a.n,1,null,null,null],[-1,5,["NextMeetingItemViewModel","HighlightMeetingTime"],[_for.a.b,_for.a.bo],null,"ms-fcl-r",null,null,0,null,null,null]],[[-1,0,["AgendaButtonTooltipText"],[_for.a.bs],null,"Title",null,_for.a.U,1,null,null,null],[-1,0,["OpenAgendaContextPeekCommand"],[_for.a.t],null,"ClickCommand",null,_for.a.n,1,null,null,null]],[[-1,4,null,null,null,"Id",null,_for.a.u,0,null,null,null,_for.c.a()]],[[-1,0,["AgendaButtonLabelText"],[_for.a.br],null,"Text",null,_for.a.c,1,null,null,null]]]);var n=_for.a.d.childNodes[6].cloneNode(!0);var d=new _fc.a(_j.a.a(n,[0,2,1,1]));var k=new _fc.d(_j.a.a(n,[0,2,1,0]),_j.b.Instance.a(_ff.a),_j.b.Instance.a(_ff.b));var f=new _n.m(_j.a.a(n,[0,2,1]));f.A(0);f.D(3);var a=new _fc.g;var h=new _fc.c;h.U(_j.f.a(["OpenAgendaContextPeekCommand"],[_for.a.t],null,"Command",null,_for.a.j,1));h.j("ENTER");var c=new _fc.c;c.U(_j.f.a(["OpenAgendaContextPeekCommand"],[_for.a.t],null,"Command",null,_for.a.j,1));c.j("SPACE");a.a([h,c]);var t=new _b.E(_j.b.Instance.a(_b.f),_j.b.Instance.a(_b.a),_j.b.Instance.a(_j.j),_j.b.Instance.a(_ff.b));t.U(_j.f.b(2,null,null,null,"ActivationMode",null,_for.a.V,0,null,null,0)).U(_j.f.a(["AgendaContextPeekViewModel"],[_for.a.E],null,"PeekDataContext",null,_for.a.X,1)).U(_j.f.a(["AgendaContextPeekViewModel","IsShown"],[_for.a.E,_for.a.bd],_for.a.bk,"IsShown",_for.a.o,_for.a.p,2,null,null,!1)).W(_j.f.a(["DOMElement"],[_for.a.m],null,"AnchorElement",null,_for.a.W,1));t.y=15;t.u(6);t.e("AgendaContextPeekView");f.C([a,t]);var e=new _n.m(_j.a.a(n,[0,2,0]));e.A(-1);var r=new _ck.f(_j.b.Instance.a(_b.f),_j.b.Instance.a(_b.a),_j.b.Instance.a(_y.a),_j.b.Instance.a(_j.j),_j.b.Instance.a(_ff.b));r.U(_j.f.b(2,null,null,null,"ActivationMode",null,_for.a.x,0,null,null,0)).U(_j.f.a(["NextMeetingItemViewModel","CalendarItemPeekViewModel"],[_for.a.b,_for.a.k],null,"PeekDataContext",null,_for.a.z,1)).U(_j.f.a(["NextMeetingItemViewModel","CalendarItemPeekViewModel","IsShown"],[_for.a.b,_for.a.k,_for.a.A],_for.a.B,"IsShown",_for.a.o,_for.a.p,2,null,null,!1)).U(_j.f.b(2,null,null,null,"ActionSource",null,_for.a.w,0,null,null,0)).W(_j.f.a(["DOMElement"],[_for.a.m],null,"AnchorElement",null,_for.a.y,1));r.K=!1;r.y=15;r.e("CalendarItemPeekView");e.C([r]);var b=new _j.i(_j.a.a(n,[0,2]));var g=new _fc.a(_j.a.a(n,[0,1,1]));var it=new _fc.a(_j.a.a(n,[0,1,0]));var tt=new _j.i(_j.a.a(n,[0,1]));var nt=new _fc.a(_j.a.a(n,[0,0,3]));var v=new _for.f(_j.a.a(n,[0,0,2]),_j.b.Instance.a(_y.a),_j.b.Instance.a(_ff.b),_j.b.Instance.a(_a.e),_j.b.Instance.a(_j.cd.$$(_h.V)));v.f=!0;var p=new _fc.a(_j.a.a(n,[0,0,1]));var w=new _fc.a(_j.a.a(n,[0,0,0]));var u=new _n.m(_j.a.a(n,[0,0]));u.A(0);u.D(3);var l=new _fc.g;var o=new _fc.c;o.U(_j.f.a(["NextMeetingItemViewModel","OpenCalendarItemPeekCommand"],[_for.a.b,_for.a.l],null,"Command",null,_for.a.j,1));o.j("ENTER");var s=new _fc.c;s.U(_j.f.a(["NextMeetingItemViewModel","OpenCalendarItemPeekCommand"],[_for.a.b,_for.a.l],null,"Command",null,_for.a.j,1));s.j("SPACE");l.a([o,s]);u.C([l]);var y=new _j.i(n.children[0]);return new _j.a(n,[y,u,w,p,v,nt,tt,it,g,b,e,f,k,d])},"",_for.b,_j.c,function(n){return new _j.c(n)},!1,!1,!1,0,_for.a.a)};ForesightComponent.registerClass("ForesightComponent",null,_a.ki,_j.ce);_for.i.registerClass("_for.i",_h.u,_h.eK,_j.bs,Sys.IDisposable);_for.d.registerClass("_for.d",_a.bw,_y.gp,_a.kV,_j.bs,Sys.IDisposable,_ff.t);_for.j.registerClass("_for.j",_a.bw,Sys.IDisposable);_for.l.registerClass("_for.l",_for.j);_for.b.registerClass("_for.b",_a.bw,_y.gM,_a.kV,_j.bs,Sys.IDisposable);_for.h.registerClass("_for.h",_fce.a);_for.g.registerClass("_for.g",_fce.e);_for.m.registerClass("_for.m",null,_j.bP);_for.f.registerClass("_for.f",_j.c);ForesightComponent.$$cctor();_for.b.a=_a.a.dF;_for.a.d=_for.a.K();_for.a.g=null;_for.a.i=null;_for.a.h=null;_for.a.a={};_for.a.$$cctor();
window.scriptsLoaded['microsoft.owa.foresight.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.foresight.js'] = (new Date()).getTime();
