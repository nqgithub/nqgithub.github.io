﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['microsoft.owa.moderngroups.shared.js'] = (new Date()).getTime();
Type.registerNamespace("_xs");_xs.s=function(){};_xs.s.registerInterface("_xs.s");var IGroupManagementHeaderViewModel=function(){};IGroupManagementHeaderViewModel.registerInterface("IGroupManagementHeaderViewModel");_xs.l=function(){};_xs.l.registerInterface("_xs.l");_xs.m=function(){};_xs.m.registerInterface("_xs.m");var IMeetNowPopoutViewModel=function(){};IMeetNowPopoutViewModel.registerInterface("IMeetNowPopoutViewModel");_xs.t=function(){};_xs.t.registerInterface("_xs.t");_xs.e=function(){};_xs.e.prototype={none:0,groupHeader:1,groupReadCard:2,groupMemberList:3,groupSettingsPanel:4};_xs.e.registerEnum("_xs.e",!1);_xs.r=function(){};_xs.r.registerInterface("_xs.r");var IGroupSearchViewModelFactory=function(){};IGroupSearchViewModelFactory.registerInterface("IGroupSearchViewModelFactory");_xs.c=function(){};_xs.c.registerInterface("_xs.c");_xs.A=function(){};_xs.A.registerInterface("_xs.A");_xs.q=function(){};_xs.q.registerInterface("_xs.q");_xs.z=function(){};_xs.z.registerInterface("_xs.z");_xs.p=function(){};_xs.p.registerInterface("_xs.p");_xs.k=function(n,t,i){_xs.k.initializeBase(this,[n.a(),i,null,t,null,null])};_xs.w=function(){};_xs.w.prototype={public:1,private:2,secret:3,recommendation:4,hiddenMembership:5};_xs.w.registerEnum("_xs.w",!1);_xs.d=function(){};_xs.d.prototype={unsupported:-1,allMessages:0,replyAndCalendar:1,replyOnly:2,none:3};_xs.d.registerEnum("_xs.d",!1);_xs.a=function(){};_xs.a.registerInterface("_xs.a");_xs.v=function(){};_xs.v.registerInterface("_xs.v");_xs.n=function(){};_xs.n.registerInterface("_xs.n");_xs.o=function(){};_xs.o.registerInterface("_xs.o");_xs.i=function(n){this.a=n};_xs.i.prototype={a:null};function ModernGroupsSharedComponent(){}ModernGroupsSharedComponent.$$cctor=function(){_a.t.a().a(ModernGroupsSharedComponent)};ModernGroupsSharedComponent.prototype={b:function(n,t,i){var u=this;n.b(_xs.k,function(){return new _xs.k(n.a(_y.a),n.a(_a.e),n.c(_xs.c))}).a();var r=this;n.b(_xs.u,function(){return new _xs.u(n.a(_a.e))}).b(_xs.g).a()},a:function(){return[]}};_xs.j=function(n){this.a=n};_xs.j.prototype={a:null};_xs.b=function(){_xs.b.initializeBase(this)};_xs.b.prototype={a:function(){return this.eK(_xs.b.e)},j:function(n){this.eI(_xs.b.e,n);return n},b:function(){return this.eK(_xs.b.a)},f:function(n){this.eI(_xs.b.a,n);return n},d:function(){return this.eK(_xs.b.c)},h:function(n){this.eI(_xs.b.c,n);return n},e:function(){return this.eK(_xs.b.d)},i:function(n){this.eI(_xs.b.d,n);return n},c:function(){return this.eK(_xs.b.b)},g:function(n){this.eI(_xs.b.b,n);return n}};_xs.f=function(){this.l=0};_xs.f.prototype={m:null,n:null,p:null,l:0,o:null,q:!1,e:function(){return this.q},c:function(n){this.q=n;return n},v:null,f:function(){return this.v},r:!1,g:function(){return this.r},j:function(n){this.r=n;return n},w:!1,h:function(){return this.w},x:!1,i:function(){return this.x},t:null,b:function(){return this.t},d:function(n){this.t=n;return n},s:0,a:function(){return this.s},k:function(n){this.s=n;return n},u:null};_xs.g=function(){};_xs.g.registerInterface("_xs.g");_xs.u=function(n){_j.s.b(n,"flightManager");this.c=n};_xs.u.prototype={c:null,a:function(n){_j.s.d(n,"groupSmtpAddress");return this.c.a()&&this.c.a().bQ().Enabled?!0:!1},b:function(){return this.c.a()&&this.c.a().bl().Enabled?!0:!1}};_xs.h=function(){};_xs.h.a=function(n,t,i,r,u,f){if(f){_j.e.a(_a.a.bH,"Updating local unread count on MarkAsRead with groupSmtpAddress: {0}, unreadMessagesInConversationsCount: {1}, messagesinConversationsCount: {2}, markRead: {3}",n,i,r,u);var e=0;if(u)e=t.b-i;else{var o=r-i;e=t.b+o}t.f(e)}};_xs.h.d=function(n,t,i){if(i){_j.e.a(_a.a.bH,"Updating local unread count on MarkAllAsRead with groupSmtpAddress: {0}",n);t.f(0)}};_xs.h.b=function(n,t,i,r){if(r){_j.e.a(_a.a.bH,"Updating local unread count on DeleteConversation with groupSmtpAddress: {0}, unreadMessagesInConversationCount: {1}",n,i);t.f(t.b-i)}};_xs.h.c=function(n,t,i,r){if(r){_j.e.a(_a.a.bH,"Updating local unread count on DeleteItem with groupSmtpAddress: {0}, isItemUnread: {1}",n,i);i&&t.f(t.b-1)}};_xs.x=function(){};_xs.x.registerInterface("_xs.x");_xs.y=function(){};_xs.y.registerInterface("_xs.y");_xs.B=function(){};_xs.B.registerInterface("_xs.B");_xs.k.registerClass("_xs.k",_y.be);_xs.i.registerClass("_xs.i");ModernGroupsSharedComponent.registerClass("ModernGroupsSharedComponent",null,_a.ki,_j.ce);_xs.j.registerClass("_xs.j");_xs.b.registerClass("_xs.b",_a.co,_xs.v);_xs.u.registerClass("_xs.u",null,_xs.g);ModernGroupsSharedComponent.$$cctor();_xs.b.e=new _a.f("SharePointUrl",String,_xs.b);_xs.b.a=new _a.f("DocumentsUrl",String,_xs.b);_xs.b.c=new _a.f("NotebookUrl",String,_xs.b);_xs.b.d=new _a.f("PlannerUrl",String,_xs.b);_xs.b.b=new _a.f("IntegrationsUrl",String,_xs.b);
window.scriptsLoaded['microsoft.owa.moderngroups.shared.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['microsoft.owa.moderngroups.shared.js'] = (new Date()).getTime();