﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.modernbootreadingpane.js'] = (new Date()).getTime();
function ModernBootReadingPaneComponent(){}ModernBootReadingPaneComponent.$$cctor=function(){_a.t.a().a(ModernBootReadingPaneComponent)};ModernBootReadingPaneComponent.prototype={b:function(n,t,i){var u=this;n.b(IModernConversationItemPartsFactory,function(){return new ConversationItemPartsFactory(n.a(_a.cu),n.a(_h.Z),n.a(_a.x),i)});var r=this;n.b(_h.bH,function(){return new _bmr.d(n.a(_a.cu),n.a(_a.x),n.a(_a.br),n.a(_h.Z),i)})},a:function(){return null}};Type.registerNamespace("_bmr");_bmr.b=function(){};_bmr.b.registerInterface("_bmr.b");_bmr.a=function(n,t,i,r,u,f){this.bw=Function.createDelegate(this,this.co);this.bv=Function.createDelegate(this,this.cl);this.bu=Function.createDelegate(this,this.cf);this.bt=Function.createDelegate(this,this.cd);this.bO=Function.createDelegate(this,this.cn);this.bN=Function.createDelegate(this,this.cm);this.bx=Function.createDelegate(this,this.cq);this.by=Function.createDelegate(this,this.cr);this.bM=Function.createDelegate(this,this.cj);this.D=new _j.l;this.S={};this.M={};this.bs=new _a.k;this.bf=new _a.k;this.bo=new _j.q;this.R=undefined;this.bp=new Sys.EventHandlerList;this.P=new Sys.EventHandlerList;_bmr.a.initializeBase(this);this.E=t;this.bh=i;this.bc=n;this.bm=r;this.G=u;this.bg=f;this.D.e(this.bM);this.G&&this.G.a().bI().Enabled&&(this.bq=!0)};_bmr.a.prototype={G:null,bg:null,bh:null,bm:!1,E:null,K:20,bc:0,V:null,bA:null,bJ:0,Z:0,N:!1,bI:!1,bK:!1,be:!1,bd:!1,bl:!1,O:0,bk:!1,bb:null,bD:!1,br:"",L:!1,bq:!1,T:null,H:null,C:null,bC:0,X:!1,bn:!1,bj:!1,Y:null,ba:0,U:0,I:null,o:function(){return this.E},g:function(){return this.D.x.length},a:function(){return this.D},d:function(){return this.N},bW:function(n){this.N=n;this.eH("Loading");return n},j:function(){return this.bk},bG:function(n){if(this.bk!==n){this.bk=n;this.eH("IsLoadMoreInProgress")}return n},f:function(){return this.be},bF:function(n){if(this.be!==n){this.be=n;this.eH("CanLoadMore")}return n},x:function(){return this.bd},bU:function(n){if(this.bd!==n){this.bd=n;this.eH("CanDelete")}return n},y:function(){return this.bl},bV:function(n){if(this.bl!==n){this.bl=n;this.eH("IsLocked")}return n},B:function(){return this.O},bH:function(n){if(this.O!==n){this.O=n;this.eH("TotalConversationNodesCount");this.eH("ReplyCountLabel")}return n},A:function(){var n=this.O-1;return String.format(_a.bH.e(n,_u.n.Sj,_u.n.R,_u.n.EJ),n)},p:function(){return this.bD},h:function(n){this.bD=n;return n},c:function(){return this.bb},v:function(n){this.L=n;return n},e:function(){return this.bs},b:function(){return this.bf},s:function(){return this.X||this.bn?"":this.br},r:function(){return this.bo.i()},k:function(n){return this.M[n]},z:function(){var n=this.P.getHandler("update");n&&n();this.bE();this.C=null;this.bT()},Q:function(){},q:function(n){if(this.K>=100){this.bF(!1);return!1}else{this.K=Math.min(this.K+10,100);var t=this.C||this.H;this.X=!0;this.W(t,200,n);this.bG(!0);return!0}},l:function(n,t,i){this.bT();this.bF(!1);var r=this.C||this.H;this.bn=!0;this.R=t;this.bj=i;this.W(r,200,n)},t:function(n){for(var f=this.D,u=0;u<f.x.length;u++){var e=f.x[u];var t=e.a();if(t)for(var i=0;i<t.b();i++){var r=_h.d.a().a(t.a(i).bH.ItemId.Id);if(r){n(r);if(r.dh){this.L=!0;break}}}if(this.L)break}},n:function(n){return this.L?!0:this.C?this.bz(n,this.C.V(),this.C.bH.GlobalUnreadCount,this.C.bH.GlobalMessageCount):this.N?this.bz(n,this.Y,this.ba,this.U):this.bz(n,this.bA,this.bJ,this.Z)},i:function(n,t,i){if(this.E.Id!==n.bH.ConversationId.Id)throw Error.argument("conversation.Id");if(this.L){this.l(i);return!0}if(this.n(n)){this.K+=this.cc(n);this.W(n,t,i);return!0}else if(this.N){i&&this.P.addHandler("update",i);return!0}return!1},w:function(n,t){if(this.E.Id!==n.bH.ConversationId.Id)throw Error.argument("conversation.Id");if(this.G&&this.G.a().g().Enabled){if(this.H)this.W(n,203,t);else if(!this.T){this.Y=n.V();this.ba=n.bH.GlobalUnreadCount;this.U=n.bH.GlobalMessageCount;this.T=t;this.bS(n)}}else this.W(n,201,t)},m:function(n,t){var i=null;var u=n.InternetMessageId;if(!(u in this.M)){var r=new _g.ck(u);r.ParentInternetMessageId=t;Array.add(r.Items,n);i=new _g.cd(r);this.R==="ChronologicalNewestOnTop"||this.R==="NewestOnTop"?this.D.t(0,i):this.D.a(i);this.bH(this.O+1)}return i},u:function(n){var o=n.InternetMessageId;var r=this.M[o];_j.e.a(_a.a.x,"Replacing internetMessageId "+n.InternetMessageId);var t=null;if(r){for(var i=-1,e=!1,f=0;f<r.a().b();f++){var u=r.a().a(f);if(_bc.h.a(u.bH.ItemId)){_j.e.a(_a.a.x,"Found client id"+u.bH.ItemId);i=f}else if(n.ItemId.Id===u.bH.ItemId.Id){_j.e.a(_a.a.x,"Found server id"+u.bH.ItemId.Id);e=!0;t=u}}if(e){if(i>=0){r.a().o(i);_j.e.a(_a.a.x,"Remove client item "+o)}}else{t=_g.f.a(n);if(i>=0){r.a().C(i,t);_j.e.a(_a.a.x,"Replace client item with server item "+n.InternetMessageId+" at "+i)}else{r.a().c(t);_j.e.a(_a.a.x,"Append server item "+n.ItemId.Id)}}}else t=_g.f.a(n);return t},bi:function(n,t){return _h.bd.a(n,t.bH.ConversationId.Id,t.bH.ConversationId.ChangeKey,this.K,t.V(),null,"ModernItemPart",this.s(),!this.bm,this.R,this.bj,1,"",this.G,this.bg,this.bq)},bS:function(n){this.H=n;var t=this.bi(201,n);t.c(this.by);t.a(this.bx);_a.g.a.a(t)},cr:function(n){if(this.D){var t=n.j[0];this.bH(t.Conversation.TotalConversationNodesCount);this.bU(t.Conversation.CanDelete);this.bV(t.Conversation.IsLocked);this.bX(t.Conversation.ConversationNodes);this.bQ(t.Conversation);this.br=t.Conversation.SyncState;this.bZ()}},cq:function(n){if(this.T){this.T();this.T=null}},W:function(n,t,i){this.C=n;this.bC=t;i&&this.bp.addHandler("update",i);this.N||this.bB()},bz:function(n,t,i,r){if(t){if(!n.V())return!0;if(t.a(n.V())>0)return!1}return!t||!n.V()?!0:t.a(n.V())<0||i!==n.bH.GlobalUnreadCount||r!==n.bH.GlobalMessageCount?!0:!1},cc:function(n){var t=0;if(this.L)return t;this.C?t=n.bH.GlobalMessageCount-this.C.bH.GlobalMessageCount:this.N?t=n.bH.GlobalMessageCount-this.U:this.Z>0&&(t=n.bH.GlobalMessageCount-this.Z);return Math.max(t,0)},bB:function(){_j.e.a(_bmr.a.a,"Loading item parts for conversation with id {0}.",this.C.bH.ConversationId.Id);this.H=this.C;this.bc=this.bC;this.P=this.bp;this.bo.f();this.Y=this.H.V();this.ba=this.H.bH.GlobalUnreadCount;this.U=this.H.bH.GlobalMessageCount;var n=this.bi(this.bc,this.C);n.b(this.bN);n.c(this.bO);this.V=n;this.C.K&&(this.I=this.C);this.C=null;this.bp=new Sys.EventHandlerList;this.X=!1;this.bn=!1;this.L=!1;this.bW(!0);this.bG(this.X);_a.g.a.a(n)},bX:function(n){n||(n=[]);this.cs(n);var i=this,r=this,t=this;_h.R.a(this.D,n,function(n){return n.bH.InternetMessageId},function(n){return n.InternetMessageId},function(n,i){var r=n?n:new _g.cd;t.ce(r,i);return r},!0,!1,_bmr.a.a);this.bF(this.D.x.length<this.O)},cs:function(n){_j.e.a(_a.a.x,"Pre-preserve: current="+this.D.x.length+", new="+n.length);var i="OQC:"+this.E.Id;var t=this.bh.c[i];this.bP(n,t);i="OMC:"+this.E.Id;t=this.bh.c[i];this.bP(n,t);_j.e.a(_a.a.x,"Post-preserve: current="+this.D.x.length+", new="+n.length)},bP:function(n,t){if(t&&!t.bf())for(var e=n.length,r=0;r<t.a().d.length;r++){for(var f=t.a().d[r],i=e-1;i>=0;){var o=n[i];if(o.InternetMessageId===f)break;i--}if(i<0){var u=this.M[f];u&&Array.add(n,u.bH)}}},cn:function(n){if(n===this.V){var i=this.P.getHandler("update");this.bb=n.G;this.bE();var t=n.j[0];this.bH(t.Conversation.TotalConversationNodesCount);this.bU(t.Conversation.CanDelete);this.bV(t.Conversation.IsLocked);this.bX(t.Conversation.ConversationNodes);this.bQ(t.Conversation);this.br=t.Conversation.SyncState;this.bZ();this.ct(t.Conversation);i&&i();if(this.C){_j.e.a(_bmr.a.a,"Found pending update request for conversation with id {0}.",this.C.bH.ConversationId.Id);this.bB()}}},ct:function(n){if(this.I&&this.I.bH.ConversationId.Id===n.ConversationId.Id){this.I.A(n.TotalConversationNodesCount);if(n.ConversationNodes&&n.ConversationNodes.length>this.I.a().b()){this.I.a().m();for(var i=0;i<n.ConversationNodes.length;i++){var t=n.ConversationNodes[i];if(t.Items&&t.Items.length>0){var u=t.Items[0];var r=new _g.e(u.ItemId.Id);r.ChangeKey=u.ItemId.ChangeKey;this.I.a().c(r)}}}this.I=null}},bQ:function(n){if(n.ToRecipients){this.bs.m();this.bs.g(n.ToRecipients)}if(n.CcRecipients){this.bf.m();this.bf.g(n.CcRecipients)}},cm:function(n){if(n===this.V){this.I=null;var t=this.P.getHandler("update");this.bb=n.G;this.bE();t&&t();if(this.C){_j.e.a(_bmr.a.a,"Found pending update request for conversation with id {0}.",this.C.bH.ConversationId.Id);this.bB()}}},bE:function(){this.P=new Sys.EventHandlerList;this.V=null;this.bW(!1);this.bG(!1)},ce:function(n,t){n.p(t.IsRootNode);t.InternetMessageId&&n.n(t.InternetMessageId);t.ParentInternetMessageId&&n.q(t.ParentInternetMessageId);t.QuotedTextList&&n.r(new _a.k(t.QuotedTextList));t.IsQuotedTextChanged&&n.o(t.IsQuotedTextChanged);t.HasQuotedText&&n.l(!0);t.NewParticipants&&n.h(new _a.k(t.NewParticipants));t.InReplyToItem&&n.m(t.InReplyToItem);var r=this,u=this,i=this;_h.R.a(n.a().f,t.Items,function(n){return n.bH.ItemId.Id},function(n){return n.ItemId.Id},function(n,t){if(n){i.bY(n,t);return n}else{var r=_h.d.a().a(t.ItemId.Id);if(r){i.bY(r,t);return r}else return _g.f.a(t)}},!0,!1,_bmr.a.a);this.bo.c(n.bH.InternetMessageId)},bY:function(n,t){if(t.ContainsOnlyMandatoryProperties)n.dV(t);else{t.Subject=n.bH.Subject;if(n.cf()&&!n.cf().bH.IsTruncated&&t.UniqueBody&&t.UniqueBody.IsTruncated){var u=new _g.s(n.cf().a()==="HTML"?"HTML":"Text",n.cf().bH.Value);u.IsTruncated=!0;t.UniqueBody=u}if(n.cj()){var r=new _g.s(n.cj().a()==="HTML"?"HTML":"Text",n.cj().bH.Value);r.IsTruncated=n.cj().bH.IsTruncated;t.NormalizedBody=r}if(n.X()){var i=new _g.s(n.X().a()==="HTML"?"HTML":"Text",n.X().bH.Value);i.IsTruncated=n.X().bH.IsTruncated;t.Body=i}n.k(t)}},cj:function(n,t){var e=t.a;var f=t.b;if(f)for(var o=f,c=o.length,r=0;r<c;++r){var l=o[r];this.ci(l)}if(e)for(var u=e,h=u.length,i=0;i<h;++i){var s=u[i];this.ch(s)}},ci:function(n){var t=n;delete this.M[t.bH.InternetMessageId];t.a().m();t.a().q(this.bt);if(!this.D.x.length&&!this.bK){_h.x.b().a(this.E.Id,2,this.bu);_h.x.b().a(this.E.Id,1,this.bv);this.bK=!0}},ch:function(n){var t=n;this.M[t.bH.InternetMessageId]=t;for(var i=0;i<t.a().b();i++){var r=t.a().a(i);this.bR(r,t)}t.a().p(this.bt);if(!this.bI){_h.x.b().b(this.E.Id,2,this.bu);_h.x.b().b(this.E.Id,1,this.bv);this.bI=!0}},cd:function(n,t){var r=t.a;var u=t.b;var i=null;if(u&&u.length){i=this.S[u[0].bH.ItemId.Id];for(var o=u,l=o.length,f=0;f<l;++f){var a=o[f];this.cp(a)}}if(r&&r.length){i||(i=this.cb(r[0].bH.ItemId.Id));for(var s=r,c=s.length,e=0;e<c;++e){var h=s[e];this.bR(h,i)}}i&&!i.a().b()&&this.D.p(i,!0)},cp:function(n){var t=n;delete this.S[t.bH.ItemId.Id];_h.d.a().c(t.bH.ItemId.Id);t.dC(this.bw)},bR:function(n,t){this.S[n.bH.ItemId.Id]=t;_h.d.a().d(n.bH.ItemId.Id)?_h.d.a().e(n.bH.ItemId.Id):_h.d.a().b(n.bH.ItemId.Id,n);n.dE(this.bw)},co:function(n,t){var r=n;var i=this.S[r.bH.ItemId.Id];i&&i.a().l(r)},cf:function(n,t){for(var f=n,i=0;i<f.a().b();i++){var e=f.a().a(i).Id;var r=this.S[e];var u=_h.d.a().a(e);u&&r&&r.a().l(u)}},cl:function(n,t){var r=n;var i=t;i.a==="UnreadCount"?this.ck(r):i.a==="GlobalUnreadCount"&&this.cg(r)},ck:function(n){var r=!1;if(n.bH.UnreadCount===n.a().b())r=!1;else if(n.bH.UnreadCount)return;else r=!0;for(var i=0;i<n.a().b();i++){var t=_h.d.a().a(n.a().a(i).Id);t&&t.dj()&&t.h(r)}},cg:function(n){var r=!1;if(n.bH.GlobalUnreadCount===n.c().b())r=!1;else if(n.bH.GlobalUnreadCount)return;else r=!0;for(var i=0;i<n.c().b();i++){var t=_h.d.a().a(n.c().a(i).Id);t&&t.dj()&&t.h(r)}},cb:function(n){for(var t=0;t<this.D.x.length;t++){var i=this.D.x[t];if(this.ca(i,n))return i}return null},ca:function(n,t){if(!n||!n.a())return!1;for(var i=0;i<n.a().b();i++)if(n.a().a(i).bH.ItemId.Id===t)return!0;return!1},bT:function(){for(var i=this.D.x.length-1;i>=0;--i)for(var t=this.D.x[i],n=t.a().b()-1;n>=0;--n){var r=t.a().a(n);t.a().o(n)}},bZ:function(){this.bA=this.Y;this.Z=this.U;this.bJ=this.ba}};function ConversationItemPartsFactory(n,t,i,r){this.c=n;this.e=t;this.d=i;this.b=r}ConversationItemPartsFactory.prototype={c:null,e:null,d:null,b:null,a:function(n,t){return new _bmr.a(n,t,this.c,this.e.a(),this.d,this.b)}};_bmr.c=function(n,t,i,r,u,f,e){_bmr.c.initializeBase(this,[n,t,i,e,r,u]);this.K=4;this.R="ChronologicalNewestOnBottom";this.bL=f};_bmr.c.prototype={bL:null,cu:function(){return!!this.G&&this.G.a().fm().Enabled&&!this.G.a().bI().Enabled},bi:function(n,t){var r=t.bH.FolderId;var i=r.a.Mailbox.EmailAddress;return _h.bd.a(n,t.bH.ConversationId.Id,t.bH.ConversationId.ChangeKey,this.K,t.V(),null,"ModernItemPart",this.s(),!this.bm,"ChronologicalNewestOnBottom",this.bj,2,i,this.G,this.bg,this.bq,this.cu(),this.bL)},bS:function(n){this.H=n;var t=this.bi(702,n);t.c(this.by);t.a(this.bx);_a.g.a.a(t)}};_bmr.d=function(n,t,i,r,u){_bmr.d.initializeBase(this,[n,r,t,u]);this.f=i};_bmr.d.prototype={f:null,a:function(n,t){return new _bmr.c(n,t,this.c,this.d,this.b,this.f,this.e.a())}};ModernBootReadingPaneComponent.registerClass("ModernBootReadingPaneComponent",null,_a.ki,_j.ce);_bmr.a.registerClass("_bmr.a",_a.co,_h.bO,_bmr.b,IConversationItemParts,_j.bs,Sys.IDisposable);ConversationItemPartsFactory.registerClass("ConversationItemPartsFactory",null,IModernConversationItemPartsFactory,IConversationItemPartsFactory);_bmr.c.registerClass("_bmr.c",_bmr.a);_bmr.d.registerClass("_bmr.d",ConversationItemPartsFactory,_h.bH,IConversationItemPartsFactory);ModernBootReadingPaneComponent.$$cctor();_bmr.a.a=_a.a.U;
window.scriptsLoaded['microsoft.owa.modernbootreadingpane.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.modernbootreadingpane.js'] = (new Date()).getTime();
