﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.core.introductionpeek.js'] = (new Date()).getTime();
function IntroductionPeekComponent(){}IntroductionPeekComponent.$$cctor=function(){_a.t.a().a(IntroductionPeekComponent)};IntroductionPeekComponent.prototype={b:function(n,t,i){var u=this;n.b(_y.ii,function(){return new _ip.e(n.d(_y.cc),n.a(_y.a))});var r=this;n.b(_y.bC,function(){return new _ip.d(n.a(_ff.a),n.a(_g.h),n.a(_h.n),n.a(_a.q),n.a(_j.j),n.a(_y.ii))})},a:function(){return[]}};Type.registerNamespace("_ip");_ip.c=function(n,t,i,r,u,f,e,o,s,h,c,l,a){this.t=Function.createDelegate(this,this.M);this.s=Function.createDelegate(this,this.L);this.r=Function.createDelegate(this,this.K);this.u=Function.createDelegate(this,this.P);this.v=Function.createDelegate(this,this.Q);this.w=Function.createDelegate(this,this.R);this.C=Function.createDelegate(this,this.O);_ip.c.initializeBase(this);_a.c.a(n,"layoutSettings");_a.c.a(t,"userOptions");_a.c.a(i,"inferenceTracker");_a.c.a(u,"eventAggregator");_a.c.a(r,"actionManager");_a.c.a(f,"introductionPeekContentViewModelFactory");_a.c.c(e,"peekContentTitle");_a.c.c(o,"peekContentDescription");_a.c.b(s,"helpId");this.E=n;this.h=t;this.j=i;this.x=r;this.i=u;this.T(new _j.g(this.C,_a.a.cR));this.o=e;this.n=o;this.m=s;this.p=h;this.q=c;this.g=l;if(!_j.h.a(a)){this.A=!0;this.B=a}this.N(f)};_ip.c.prototype={h:null,E:null,j:null,i:null,x:null,o:null,n:null,m:0,p:null,q:null,B:"",A:!1,g:0,f:null,D:null,y:!1,z:!1,d:function(){return this.f},I:function(n){if(this.f!==n){this.f=n;this.eH("IntroductionPeekContentViewModel")}return n},T:function(n){this.D=n;this.eH("EnterKeyCommand");return n},H:function(n){if(this.y!==n){this.y=n;this.eS("CanShowIntroduction")}return n},b:function(n){this.eM("CanShowIntroduction",n)},c:function(n){this.eO("CanShowIntroduction",n)},e:function(){if(this.f){this.f.a(_y.Z.b(this.g));this.f.c()&&this.j.D(this.g);return this.f.c()}return!1},a:function(n){if(this.f.c()){if(n){this.j.C(this.g);this.l(n)}else this.f.a(!1);return!this.f||!this.f.c()}return!1},eJ:function(){this.z&&this.V();this.g===4&&this.f.rpcl("IsPeekContentShownAndClosedInTNarrow",this.w);_a.gd.prototype.eJ.call(this)},O:function(){this.e()},N:function(n){if(_y.Z.b(this.g)){var u=this;var r=new _j.g(function(){u.G()},_a.a.cR);var t=null;if(this.p){var i=this;t=new _j.g(function(){i.S();i.p.d()},_a.a.cR)}this.A?this.I(n.b(this.o,this.n,this.m,this.B,r,t,this.q,this.v,this.u,this.g)):this.I(n.a(this.o,this.n,this.m,r,t,this.q,this.v,this.u,this.g));this.g===4&&this.f.apcl("IsPeekContentShownAndClosedInTNarrow",this.w);this.H(!0);this.U();this.z=!0}},G:function(){this.j.C(this.g);this.l(!0)},l:function(n){if(this.f){this.f.a(!1);this.H(!1);if(n){switch(this.g){case 1:this.h.G(this.h.z()|8);break;case 2:this.h.G(this.h.z()|16);break;case 4:this.h.G(this.h.z()|128);break;case 3:this.h.G(this.h.z()|32);break;case 7:this.h.G(this.h.z()|512);break;case 14:this.h.G(this.h.z()|65536);break}_h.f.a(this.h.u,this.x)}}},Q:function(){this.j.D(this.g)},R:function(n,t){this.G()},S:function(){this.j.bI(this.g);this.l(!0)},P:function(){this.j.bH(this.g);this.l(!1)},U:function(){this.i.b(_y.eI,this.r);this.i.b(_y.cI,this.s);this.i.b(_y.bO,this.t)},V:function(){this.i.c(_y.eI,this.r);this.i.c(_y.cI,this.s);this.i.c(_y.bO,this.t)},K:function(n){this.a(!1)},L:function(n){this.a(!1)},M:function(n){this.a(!1)}};_ip.d=function(n,t,i,r,u,f){_a.c.a(t,"userConfiguration");this.f=n;this.g=t.a();this.d=i;this.c=u;this.b=r;this.e=f};_ip.d.prototype={g:null,f:null,d:null,c:null,b:null,e:null,a:function(n,t,i,r,u,f){return new _ip.c(this.f,this.g,this.d,this.b,this.c,this.e,n,t,i,r,u,f)}};_ip.b=function(n,t,i,r,u,f,e,o,s,h,c,l,a){_ip.b.initializeBase(this);this.f=n;this.u=t;this.i=h;this.j=s;this.n=i;this.d=r;this.e=u;this.g=c;this.s=f;this.o=e;this.r=o;var v=this;this.t=new _j.g(function(){v.A()},_a.a.cR);this.m=this.x()?this.g===4?315:275:300;this.l=300;if(l){_a.c.c(a,"VideoPlayerUrl cannot be null when showVideoPlayer is true");this.v=l;this.w=a;this.l=600;this.m=700}};_ip.b.prototype={f:null,s:null,t:null,o:null,r:null,w:"",n:null,d:null,e:0,v:!1,g:0,l:0,m:0,b:!1,j:null,i:null,u:null,z:function(){return _j.h.a(this.r)?_nbs.a.qO:this.r},y:function(){return!this.o&&this.e!==-1},p:function(){return this.l},q:function(){return this.m},h:function(){return!_j.h.a(this.n)&&!_j.h.a(this.d)},c:function(){return this.b},a:function(n){if(this.b!==n){this.b=n;this.b&&this.j&&this.j();!this.b&&this.x()&&this.eH("IsPeekContentShownAndClosedInTNarrow");this.eH("IsShown")}return n},x:function(){return this.u.a()==="TouchNarrow"},A:function(){if(this.f){var n=this;this.f.a(function(t){t.a(n.e)})}this.i&&this.i()}};_ip.e=function(n,t){_a.c.a(n,"helpProvider");this.c=n;this.d=t};_ip.e.prototype={d:null,c:null,a:function(n,t,i,r,u,f,e,o,s){return new _ip.b(this.c,this.d,n,t,i,r,u,f,e,o,s)},b:function(n,t,i,r,u,f,e,o,s,h){return new _ip.b(this.c,this.d,n,t,i,u,f,e,o,s,h,!0,r)}};_ip.a=function(){};_ip.a.$$cctor=function(){_ip.a._I()};_ip.a.q=function(){var n=window.document.createElement("DIV");n.innerHTML="<div> <span></span> </div><div> <div> <button autoid=\"_ip_0\" type='button' class='_ip_8'></button>  <div class='_ip_2'> <span autoid=\"_ip_1\" class='_ip_3 ms-font-weight-semilight ms-font-color-black'></span> <span autoid=\"_ip_2\" class='_ip_4 ms-font-weight-regular'></span> <div> <iframe class='_ip_7'></iframe> </div> </div>  <div class='_ip_5'> <a autoid=\"_ip_3\" class='_ip_6 ms-font-weight-regular ms-font-color-themePrimary'></a> <a class='_ip_6 ms-font-weight-regular ms-font-color-themePrimary'></a> </div> </div> <div>  <div class='_ip_2'> <span class='_ip_3 ms-font-weight-semilight ms-font-color-black'></span> <span class='_ip_4 ms-font-weight-regular'></span> </div> </div> </div>";_j.i.a().appendChild(n);return n};_ip.a.m=function(n){return _u.n.OF};_ip.a.o=function(n){return n.z()};_ip.a.l=function(n){return n.g===4};_ip.a.w=function(n){return n.s};_ip.a.i=function(n){return n.n};_ip.a.h=function(n){return n.d};_ip.a.z=function(n){return n.v};_ip.a.A=function(n){return n.w};_ip.a.y=function(n){return n.y()};_ip.a.x=function(n){return n.t};_ip.a.n=function(n){return n.o};_ip.a.b=function(n,t){n.a(t)};_ip.a.c=function(n,t){n.Q(t)};_ip.a.d=function(n,t){n.K(t)};_ip.a.k=function(n,t){n.T(t)};_ip.a.t=function(n,t){n.l(t)};_ip.a.s=function(n,t){n.m(t)};_ip.a.r=function(n,t){n.Q(t)};_ip.a.v=function(n,t){n.bk(t)};_ip.a.u=function(n,t){n.a(t)};_ip.a.j=function(){_ip.a.f||(_ip.a.f=new _fc.k);return _ip.a.f};_ip.a.p=function(){_ip.a.g||(_ip.a.g=new _fc.l);return _ip.a.g};_ip.a._I=function(){var i="IntroductionPeekContentView._tid1";new _j.d(i,function(){_ip.a.a[i]===undefined&&(_ip.a.a[i]=[[[-1,0,["LearnMoreLinkText"],[_ip.a.m],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["LearnMoreLinkText"],[_ip.a.m],null,"AriaLabel",null,_ip.a.c,1,null,null,null]]]);var t=_ip.a.e.childNodes[0].cloneNode(!0);var n=new _fc.a(t.children[0]);n.A(0);return new _j.a(t,[n])},"",_ip.b,_fc.e,function(n){return new _fc.e(n)},!1,!0,!1,0,_ip.a.a);var t="IntroductionPeekContentView._tid2";new _j.d(t,function(){_ip.a.a[t]===undefined&&(_ip.a.a[t]=[[[-1,0,["TryFeatureCommandText"],[_ip.a.o],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["TryFeatureCommandText"],[_ip.a.o],null,"AriaLabel",null,_ip.a.c,1,null,null,null]]]);var i=_ip.a.e.childNodes[0].cloneNode(!0);var n=new _fc.a(i.children[0]);n.A(0);return new _j.a(i,[n])},"",_ip.b,_fc.e,function(n){return new _fc.e(n)},!1,!0,!1,0,_ip.a.a);var n="IntroductionPeekContentView";new _j.d(n,function(){_ip.a.a[n]===undefined&&(_ip.a.a[n]=[[[-1,0,["IsModernGroupsInTNarrow"],[_ip.a.l],null,"IsHidden",null,_ip.a.d,1,null,null,!0]],[[-1,4,null,null,null,"ImageId",null,_ip.a.t,0,null,null,null,_n.b.cB()],[-1,4,null,null,null,"HoveredImageId",null,_ip.a.s,0,null,null,null,_n.b.dh()],[-1,4,null,null,null,"AriaLabel",null,_ip.a.r,0,null,null,null,_u.R.Bt],[-1,0,["DismissCommand"],[_ip.a.w],null,"ClickCommand",null,_ip.a.k,1,null,null,null]],[[-1,0,["Title"],[_ip.a.i],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["Title"],[_ip.a.i],null,"AriaLabel",null,_ip.a.c,1,null,null,null]],[[-1,0,["Description"],[_ip.a.h],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["Description"],[_ip.a.h],null,"AriaLabel",null,_ip.a.c,1,null,null,null]],[[-1,0,["ShowVideoPlayer"],[_ip.a.z],null,"IsHidden",null,_ip.a.d,1,_ip.a.j(),null,!0]],[[-1,4,null,null,null,"Title",null,_ip.a.v,0,null,null,null,_u.R.QG],[-1,0,["VideoPlayerUrl"],[_ip.a.A],null,"Source",null,_ip.a.u,1,null,null,null]],[[-1,0,["ShowLearnMoreLink"],[_ip.a.y],null,"IsHidden",null,_ip.a.d,1,_ip.a.j(),null,!0],[-1,0,["LearnMoreCommand"],[_ip.a.x],null,"ClickCommand",null,_ip.a.k,1,null,null,null]],[[-1,0,["TryFeatureCommand"],[_ip.a.n],null,"IsHidden",null,_ip.a.d,1,_ip.a.p(),null,!0],[-1,0,["TryFeatureCommand"],[_ip.a.n],null,"ClickCommand",null,_ip.a.k,1,null,null,null]],[[-1,0,["IsModernGroupsInTNarrow"],[_ip.a.l],null,"IsHidden",null,_ip.a.d,1,_ip.a.j(),null,!0],[-1,5,["IsModernGroupsInTNarrow"],[_ip.a.l],null,"_ip_9",null,null,0,null,null,null]],[[-1,0,["Title"],[_ip.a.i],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["Title"],[_ip.a.i],null,"AriaLabel",null,_ip.a.c,1,null,null,null]],[[-1,0,["Description"],[_ip.a.h],null,"Text",null,_ip.a.b,1,null,null,null],[-1,0,["Description"],[_ip.a.h],null,"AriaLabel",null,_ip.a.c,1,null,null,null]]]);var t=_ip.a.e.childNodes[1].cloneNode(!0);var o=new _fc.a(_j.a.a(t,[1,0,1]));o.A(0);var s=new _fc.a(_j.a.a(t,[1,0,0]));s.A(0);var a=new _j.i(t.children[1]);var c=new _fc.e(_j.a.a(t,[0,2,1]));c.y("IntroductionPeekContentView._tid2");var h=new _fc.e(_j.a.a(t,[0,2,0]));h.y("IntroductionPeekContentView._tid1");var i=new _b.A(_j.a.a(t,[0,1,2,0]));i.z.parentNode.removeChild(i.z);var r=new _fce.d(_j.a.a(t,[0,1,2]));var e=new _fc.a(_j.a.a(t,[0,1,1]));e.A(0);var u=new _fc.a(_j.a.a(t,[0,1,0]));u.A(0);var f=new _fc.b(_j.a.a(t,[0,0]));f.A(0);var l=new _j.i(t.children[0]);r.a.a(i);return new _j.a(t,[l,f,u,e,r,i,h,c,a,s,o])},"",_ip.b,_j.c,function(n){return new _j.c(n)},!1,!1,!1,0,_ip.a.a)};IntroductionPeekComponent.registerClass("IntroductionPeekComponent",null,_a.ki,_j.ce);_ip.c.registerClass("_ip.c",_a.bw,_y.lb);_ip.b.registerClass("_ip.b",_a.bw,_y.gp,_a.kV,_j.bs,Sys.IDisposable);IntroductionPeekComponent.$$cctor();_ip.a.e=_ip.a.q();_ip.a.f=null;_ip.a.g=null;_ip.a.a={};_ip.a.$$cctor();
window.scriptsLoaded['microsoft.owa.core.introductionpeek.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.core.introductionpeek.js'] = (new Date()).getTime();
