(this.webpackJsonpizpswctrl3=this.webpackJsonpizpswctrl3||[]).push([[0],{59:function(e,t,n){},60:function(e,t,n){},61:function(e,t,n){"use strict";n.r(t);var r=n(1),a=n(10),c=n.n(a),s=n(3),o=n(5),u=n(2),i=n.n(u),d=n(12),l=n(4),j=n(13),p=n(6),b=n.n(p),x=function(e){var t=Object(r.useState)(""),n=Object(j.a)(t,2),a=n[0],c=n[1],s=Object(r.useState)(""),o=Object(j.a)(s,2),u=o[0],i=o[1];return{type:e,name:u,value:a,onChange:function(e){c(e.target.value),i(e.target.value)}}},f={login:function(){var e=Object(l.a)(i.a.mark((function e(t){var n;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,b.a.post("/api/login",t);case 2:return n=e.sent,e.abrupt("return",n.data);case 4:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}()},O="/api/passwords",h=null,w={getAll:function(){var e={headers:{Authorization:h}};return b.a.get(O,e).then((function(e){return e.data}))},create:function(){var e=Object(l.a)(i.a.mark((function e(t){var n,r;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n={headers:{Authorization:h}},e.next=3,b.a.post(O,t,n);case 3:return r=e.sent,e.abrupt("return",r.data);case 5:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}(),setToken:function(e){h="bearer ".concat(e)},update:function(e,t,n){var r={headers:{Authorization:h}},a={field:t,newValue:n};return b.a.put("".concat(O,"/").concat(e),a,r).then((function(e){return e.data}))},erase:function(e){var t={headers:{Authorization:h}};return b.a.delete("".concat(O,"/").concat(e),t).then((function(e){return e.data}))}},v="/api/login",m=null,g={setToken:function(e){m="bearer ".concat(e)},changePw:function(){var e=Object(l.a)(i.a.mark((function e(t){var n,r;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n={headers:{Authorization:m}},e.next=3,b.a.put("".concat(v,"/").concat(t.user),t,n);case 3:return r=e.sent,e.abrupt("return",r.data);case 5:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}(),resetUsersPsw:function(){var e=Object(l.a)(i.a.mark((function e(t){var n,r;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n={headers:{Authorization:m}},e.next=3,b.a.put("".concat(v,"/reset"),t,n);case 3:return r=e.sent,e.abrupt("return",r.data);case 5:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}(),createNewUser:function(){var e=Object(l.a)(i.a.mark((function e(t){var n,r;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n={headers:{Authorization:m}},e.next=3,b.a.post(v,t,n);case 3:return r=e.sent,e.abrupt("return",r.data);case 5:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}()},y=[],k=function(e,t){for(var n=0;n<y.length;n++)clearTimeout(y[n]);return function(){var n=Object(l.a)(i.a.mark((function n(r){return i.a.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:return n.next=2,r(T(e));case 2:y.push(window.setTimeout((function(){r(E())}),1e3*t));case 3:case"end":return n.stop()}}),n)})));return function(e){return n.apply(this,arguments)}}()},T=function(e){return{type:"NOTIFICATION",data:e}},E=function(){return{type:"CLEAR",data:""}},N=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"NOTIFICATION":return t.data;case"CLEAR":return"";default:return e}},S=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"SELECTED":return t.data;default:return e}},A=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:[],t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"LOGIN":return e.concat([t.data]);case"LOGOUT":Object(d.a)(e);return[];default:return e}},C=n(0),D={margin:"10px",padding:"8px",border:"solid 2px blue",borderRadius:"5px",width:"350px"},L=function(){var e=Object(s.b)(),t=x("text"),n=x("password");return Object(s.c)((function(e){return e.users}))===[]?null:Object(C.jsxs)("div",{style:D,children:[Object(C.jsx)("span",{className:"whiteText",children:"login:"}),Object(C.jsxs)("form",{onSubmit:function(r){r.preventDefault();var a={username:t.value,password:n.value};e(function(e){var t=e.username,n=e.password;return function(){var e=Object(l.a)(i.a.mark((function e(r){var a;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,f.login({username:t,password:n});case 3:a=e.sent,w.setToken(a.token),g.setToken(a.token),window.localStorage.setItem("uDetails",JSON.stringify(a)),r(k("welcome: ".concat(t),10)),r({type:"LOGIN",data:a}),e.next=14;break;case 11:e.prev=11,e.t0=e.catch(0),r(k("wrong credentials",10));case 14:case"end":return e.stop()}}),e,null,[[0,11]])})));return function(t){return e.apply(this,arguments)}}()}(a))},children:["username:",Object(C.jsx)("input",Object(o.a)({},t)),Object(C.jsx)("br",{}),"password:",Object(C.jsx)("input",Object(o.a)({},n)),Object(C.jsx)("br",{}),Object(C.jsx)("button",{className:"blackButtons",children:"submit login"})]})]})},I=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:[],t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"NEWLIST":var n=e.concat([]);return t.data.forEach((function(e){n.push(e)})),n;case"MODDED_LIST":return t.data;case"CLEAR_LIST":return[];case"PSW_DELETE":return t.data;default:return e}},B={margin:"10px",padding:"8px",border:"solid 2px blue",borderRadius:"5px",width:"350px"},P=function(e){var t=e.toggleShow,n=Object(s.b)(),r=x("text"),a=x("text"),c=x("text"),u=Object(s.c)((function(e){return e.users}));return u===[]?null:Object(C.jsx)("div",{style:B,children:Object(C.jsxs)("form",{onSubmit:function(e){e.preventDefault();var s={page:r.value,username:a.value,password:c.value};n(function(e,t){return function(){var t=Object(l.a)(i.a.mark((function t(n){var r;return i.a.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.prev=0,n(k("wait. working on it",6)),t.next=4,w.create(e);case 4:return t.next=6,w.getAll();case 6:r=t.sent,n(k("new entry created",5)),n({type:"MODDED_LIST",data:r}),t.next=14;break;case 11:t.prev=11,t.t0=t.catch(0),n(k("".concat(t.t0),10));case 14:case"end":return t.stop()}}),t,null,[[0,11]])})));return function(e){return t.apply(this,arguments)}}()}(s,u[0].id)),t()},children:["page:",Object(C.jsx)("input",Object(o.a)({},r)),Object(C.jsx)("br",{}),"username:",Object(C.jsx)("input",Object(o.a)({},a)),Object(C.jsx)("br",{}),"password:",Object(C.jsx)("input",Object(o.a)({},c)),Object(C.jsx)("br",{}),Object(C.jsx)("button",{className:"blackButtons",children:"save new password"})]})})},R={showModPswForm:!1,showNewPswForm:!1,showPsw:!1,showMyAccount:!1,adminTools:!1},F=function(e){return function(t){t({type:"CHANGE",data:e})}},M=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:R,t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"CHANGE":var n=Object(o.a)({},e);return n[t.data]=!e[t.data],n;case"RESET_SHOWS":return R;default:return e}},_=function(e){var t="INPUT"===e.tagName||"TEXTAREA"===e.tagName,n=document.createElement("textarea");n.style.position="absolute",n.style.left="-9999px",n.style.top="0",n.id="_hiddenCopyText_",document.body.appendChild(n),n.textContent=e;var r,a=document.activeElement;n.focus(),n.setSelectionRange(0,n.value.length);try{r=document.execCommand("copy")}catch(c){r=!1}return a&&"function"===typeof a.focus&&a.focus(),t?e.setSelectionRange(undefined,undefined):n.textContent="",r},z=function(e){var t=e.entry,n=Object(s.c)((function(e){return e.showAndHide})),r=Object(s.b)();return Object(C.jsx)("div",{className:"greenButtons",onClick:function(){var e;n.showMyAccount&&r(F("showMyAccount")),r((e=t,function(t){t({type:"SELECTED",data:e})})),r(k("password copied to clipboard, control+v to paste it somewhere",5)),_(t.password),window.scrollTo(0,0)},children:t.page})},H={margin:"10px",padding:"8px",border:"solid 2px blue",borderRadius:"5px",width:"350px"},U=function(e){var t=e.showModPswForm,n=e.entryId,r=Object(s.b)(),a=x("text"),c=x("text"),u=x("text");return Object(C.jsx)("div",{style:H,children:Object(C.jsxs)("form",{onSubmit:function(e){e.preventDefault();var s={page:a.value,username:c.value,password:u.value};r(function(e,t){return function(){var n=Object(l.a)(i.a.mark((function n(r){var a;return i.a.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:if(r(k("wait. working on it",6)),n.prev=1,""===e.page){n.next=5;break}return n.next=5,w.update(t,"page",e.page);case 5:if(""===e.username){n.next=8;break}return n.next=8,w.update(t,"username",e.username);case 8:if(""===e.password){n.next=11;break}return n.next=11,w.update(t,"password",e.password);case 11:return n.next=13,w.getAll();case 13:a=n.sent,r(k("edited selected fields.",3)),r((function(e){e({type:"SELECTED",data:""})})),r({type:"MODDED_LIST",data:a}),n.next=22;break;case 19:n.prev=19,n.t0=n.catch(1),r(k("edit failed: ".concat(n.t0),10));case 22:case"end":return n.stop()}}),n,null,[[1,19]])})));return function(e){return n.apply(this,arguments)}}()}(s,n)),t()},children:["enter new values. ",Object(C.jsx)("br",{}),Object(C.jsx)("span",{className:"whiteText",children:"leave empty values you don't want to modificate!"}),Object(C.jsx)("br",{}),"page:",Object(C.jsx)("input",Object(o.a)({},a)),Object(C.jsx)("br",{}),"username:",Object(C.jsx)("input",Object(o.a)({},c)),Object(C.jsx)("br",{}),"password:",Object(C.jsx)("input",Object(o.a)({},u)),Object(C.jsx)("br",{}),Object(C.jsx)("button",{className:"blackButtons",children:"modificate filled fields"})]})})},G=function(){var e=Object(s.b)(),t=Object(s.c)((function(e){return e.showAndHide})),n=Object(s.c)((function(e){return e.details})),r="",a=function(){e(F("showModPswForm"))},c=Object(C.jsxs)("div",{children:[Object(C.jsx)("input",{type:"button",className:"blackButtons",value:"show/hide password",onClick:function(){e(F("showPsw"))}}),Object(C.jsx)("br",{}),Object(C.jsx)("input",{type:"button",className:"blackButtons",value:"copy username",onClick:function(){_(n.username),e(k("username copied to clipboard",3))}}),Object(C.jsx)("br",{}),Object(C.jsx)("input",{type:"button",className:"yellowButtons",value:"modificate entry",onClick:function(){return a()}}),Object(C.jsx)("br",{}),Object(C.jsx)("input",{type:"button",className:"redButtons",value:"delete entry",onClick:function(){var t;window.confirm("delete psw of: ".concat(n.page,"?"))&&(e((function(e){e({type:"SELECTED",data:""})})),e((t=n.id,function(){var e=Object(l.a)(i.a.mark((function e(n){var r;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,n(k("wait. working on it",6)),e.next=4,w.erase(t);case 4:return e.next=6,w.getAll();case 6:r=e.sent,n(k("entry deleted!",3)),n((function(e){e({type:"SELECTED",data:""})})),n({type:"MODDED_LIST",data:r}),e.next=15;break;case 12:e.prev=12,e.t0=e.catch(0),n(k("delete failed: ".concat(e.t0),10));case 15:case"end":return e.stop()}}),e,null,[[0,12]])})));return function(t){return e.apply(this,arguments)}}())))}})]});return""===n&&(r=""),""!==n&&(r=t.showPsw?"password: ".concat(n.password):""),Object(C.jsxs)("div",{children:["page: ",Object(C.jsx)("span",{className:"whiteText",children:n.page}),Object(C.jsx)("br",{}),"username: ",Object(C.jsx)("span",{className:"whiteText",children:n.username}),Object(C.jsx)("br",{}),r,Object(C.jsx)("br",{}),""!==n?c:Object(C.jsx)(C.Fragment,{}),Object(C.jsx)("div",{children:t.showModPswForm?Object(C.jsx)(U,{showModPswForm:a,entryId:n.id}):Object(C.jsx)(C.Fragment,{})})]})},W=function(){var e=Object(s.b)(),t=x("password"),n=x("password"),r=x("password"),a=Object(s.c)((function(e){return e.users}));return Object(C.jsx)("div",{children:Object(C.jsxs)("form",{onSubmit:function(c){var s;c.preventDefault(),n.value!==r.value?e(k("new passwords are now equal",4)):""===t.value||""===n.value?e(k("empty fields.",4)):(e((s={user:a[0].id,current:t.value,newPsw:n.value},function(){var e=Object(l.a)(i.a.mark((function e(t){return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return t(k("working on it. wait.")),e.prev=1,e.next=4,g.changePw(s);case 4:t(k("ok, changed.")),e.next=10;break;case 7:e.prev=7,e.t0=e.catch(1),t(k("".concat(e.t0),5));case 10:case"end":return e.stop()}}),e,null,[[1,7]])})));return function(t){return e.apply(this,arguments)}}())),e(k("Password changed!.",4)))},children:[Object(C.jsx)("table",{children:Object(C.jsxs)("tbody",{children:[Object(C.jsx)("tr",{children:Object(C.jsx)("td",{className:"whiteText",children:"change accounts password"})}),Object(C.jsxs)("tr",{children:[Object(C.jsx)("td",{children:"current password:"}),Object(C.jsx)("td",{children:Object(C.jsx)("input",Object(o.a)({},t))})]}),Object(C.jsxs)("tr",{children:[Object(C.jsx)("td",{children:"new password: (min 3 characters)"}),Object(C.jsx)("td",{children:Object(C.jsx)("input",Object(o.a)({},n))})]}),Object(C.jsxs)("tr",{children:[Object(C.jsx)("td",{children:"repeat new password"}),Object(C.jsx)("td",{children:Object(C.jsx)("input",Object(o.a)({},r))})]})]})}),Object(C.jsx)("button",{type:"submit",className:"grayButtons",children:"change it."})]})})},J=function(){var e=Object(s.b)(),t=x("text"),n=x("text"),r=x("text"),a=x("text"),c=x("text"),u=function(){var r=Object(l.a)(i.a.mark((function r(a){var c;return i.a.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return a.preventDefault(),c={user:t.value,newPsw:n.value},e(k("ok, reseting",5)),r.prev=3,r.next=6,g.resetUsersPsw(c);case 6:t.value="",n.value="",e(k("reseted!",3)),r.next=14;break;case 11:r.prev=11,r.t0=r.catch(3),e(k("error: ".concat(r.t0),3));case 14:e((function(e){e({type:"RESET_SHOWS"})}));case 15:case"end":return r.stop()}}),r,null,[[3,11]])})));return function(e){return r.apply(this,arguments)}}(),d=function(){var t=Object(l.a)(i.a.mark((function t(n){var s,o;return i.a.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return n.preventDefault(),s=document.getElementById("isAdmin"),o={name:r.value,username:a.value,password:c.value,admin:!1},s.checked&&(o.admin=!0),e(k("adding new user",5)),t.prev=5,t.next=8,g.createNewUser(o);case 8:e(k("added user",5)),t.next=14;break;case 11:t.prev=11,t.t0=t.catch(5),e(k("error: ".concat(t.t0),5));case 14:case"end":return t.stop()}}),t,null,[[5,11]])})));return function(e){return t.apply(this,arguments)}}();return Object(C.jsxs)("div",{children:[Object(C.jsx)("h4",{children:"admin tools"}),Object(C.jsxs)("div",{children:[Object(C.jsx)("span",{className:"whiteText",children:"Reset password for user:"}),Object(C.jsxs)("form",{onSubmit:u,className:"adminForms",children:["username:",Object(C.jsx)("input",Object(o.a)({},t)),Object(C.jsx)("br",{}),"new password:",Object(C.jsx)("input",Object(o.a)({},n)),Object(C.jsx)("br",{}),Object(C.jsx)("button",{className:"blackButtons",children:"reset users password"})]})]}),Object(C.jsxs)("div",{children:[Object(C.jsx)("span",{className:"whiteText",children:"Create new user:"}),Object(C.jsxs)("form",{onSubmit:d,className:"adminForms",children:["name:",Object(C.jsx)("input",Object(o.a)({},r)),Object(C.jsx)("br",{}),"username:",Object(C.jsx)("input",Object(o.a)({},a)),Object(C.jsx)("br",{}),"password:",Object(C.jsx)("input",Object(o.a)({},c)),Object(C.jsx)("br",{}),"admin:",Object(C.jsx)("input",{id:"isAdmin",type:"radio",name:"rights",value:"yes"}),"yes",Object(C.jsx)("input",{type:"radio",name:"rights",value:"no"}),"no",Object(C.jsx)("br",{}),Object(C.jsx)("button",{className:"blackButtons",children:"add new user"})]})]})]})},q=(n(59),{gridArea:"atUp",backgroundColor:"black",padding:"5px"}),V={gridArea:"atLeft"},X={gridArea:"atRight"},K={gridArea:"atBottom"},Q=function(){var e=Object(s.c)((function(e){return e.users})),t=Object(s.c)((function(e){return e.passes})),n=Object(s.c)((function(e){return e.showAndHide})),a=Object(s.b)();Object(r.useEffect)((function(){a((function(e){e({type:"CLEAR_LIST"})})),a(function(){var e=Object(l.a)(i.a.mark((function e(t){var n;return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,t(k("wait. getting list",6)),e.next=4,w.getAll();case 4:n=e.sent,t(k("got password list",3)),t({type:"NEWLIST",data:n}),e.next=12;break;case 9:e.prev=9,e.t0=e.catch(0),t(k("error fetching passwords ".concat(e.t0),7));case 12:case"end":return e.stop()}}),e,null,[[0,9]])})));return function(t){return e.apply(this,arguments)}}())}),[]);var c=function(){a(F("showNewPswForm"))};return Object(C.jsx)("div",{children:Object(C.jsxs)("div",{id:"gridContainer",children:[Object(C.jsxs)("div",{id:"heads",style:q,children:["logged in as ",Object(C.jsx)("span",{className:"whiteText",children:e[0].name})," \xa0",Object(C.jsx)("button",{className:"redButtons",onClick:function(){a((function(e){e({type:"CLEAR_LIST"})})),a((function(e){e({type:"RESET_SHOWS"})})),a(function(){var e=Object(l.a)(i.a.mark((function e(t){return i.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:w.setToken(""),window.localStorage.removeItem("uDetails"),t(k("logged out.",5)),t((function(e){e({type:"SELECTED",data:""})})),t({type:"LOGOUT",data:""});case 5:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}())},children:"log out"})," \xa0",Object(C.jsx)("button",{className:"blackButtons",onClick:function(){a(F("showMyAccount"))},children:"my account"})," \xa0",e[0].admin?Object(C.jsx)("button",{className:"redButtons",onClick:function(){a(F("adminTools"))},children:"admin tools"}):Object(C.jsx)(C.Fragment,{})]}),Object(C.jsxs)("div",{id:"leftCenter",style:V,children:["saved passwords:",Object(C.jsx)("ul",{children:t.map((function(t){return t.user.id===e[0].id?Object(C.jsx)("li",{children:Object(C.jsx)(z,{entry:t})},t.id):null}))})]}),Object(C.jsxs)("div",{id:"rightCenter",style:X,children:[n.showMyAccount?Object(C.jsx)(W,{}):Object(C.jsx)(G,{}),Object(C.jsx)("div",{children:n.adminTools?Object(C.jsx)(J,{}):Object(C.jsx)(C.Fragment,{})})]}),Object(C.jsx)("div",{id:"foots",style:K,children:n.showNewPswForm?Object(C.jsx)(P,{toggleShow:c}):Object(C.jsx)("input",{className:"blackButtons",type:"button",onClick:c,value:"save new password"})})]})})},Y=function(){var e=Object(s.c)((function(e){return e.notifications}));return Object(C.jsx)("div",{style:{color:"red"},children:e})},Z={backgroundColor:"#1E1B1B",color:"#B3A3A3",padding:"10px 30px 100px 10px",border:"5px black solid",borderRadius:"5px"},$=function(){var e=Object(s.b)(),t=Object(s.c)((function(e){return e.users}));return Object(r.useEffect)((function(){e((function(e){e({type:"CLEAR_LIST"})}));var t=window.localStorage.getItem("uDetails");if(t){var n=JSON.parse(t);e(function(e){return e=JSON.parse(e),function(t){t({type:"LOGIN",data:e})}}(t)),w.setToken(n.token),g.setToken(n.token)}}),[]),Object(C.jsxs)("div",{style:Z,children:[Object(C.jsx)(Y,{}),0===t.length?Object(C.jsx)(L,{}):Object(C.jsx)(Q,{})]})},ee=n(8),te=n(27),ne=n(28),re=Object(ee.combineReducers)({users:A,passes:I,notifications:N,details:S,showAndHide:M}),ae=Object(ee.createStore)(re,Object(ne.composeWithDevTools)(Object(ee.applyMiddleware)(te.a)));n(60);c.a.render(Object(C.jsx)(s.a,{store:ae,children:Object(C.jsx)($,{})}),document.getElementById("root"))}},[[61,1,2]]]);
//# sourceMappingURL=main.d010fd57.chunk.js.map