﻿window.scriptsLoaded = window.scriptsLoaded || {}; window.scriptProcessStart = window.scriptProcessStart || {}; window.scriptProcessStart['msrcrypto-aes.js'] = (new Date()).getTime();
var msrCryptoVersion="1.01",msrCrypto=msrCrypto||function(){"use strict";function v(){function h(n){for(var t=n.length-1;t>=0;t-=1)if(n[t]+=1,n[t]>=256&&(n[t]=0),n[t])break}function c(){r=t.getVector(32);i=t.getVector(16);e=32;n=48;u=1}function l(i,r){var f,e;if(r=r||[0],r.length>n)throw new Error("Incorrect entropy or additionalEntropy length");for(r=r.concat(t.getVector(n-r.length)),i=i.concat(t.getVector((n-i.length%n)%n)),f=0;f<i.length;f+=n)e=t.xorVectors(i.slice(f,f+n),r),o(e);u=1}function o(u){for(var f=[],l=new s.aes(r),o,c;f.length<n;)h(i),o=i.slice(0,16),c=l.encrypt(o),f=f.concat(c);f=t.xorVectors(f,u);r=f.slice(0,e);i=f.slice(e)}function a(f,e){var c,l,a,v;if(f>=65536)throw new Error("too much random requested");if(u>y)throw new Error("Reseeding is required");if(e&&e.length>0){while(e.length<n)e=e.concat(t.getVector(n-e.length));o(e)}else e=t.getVector(n);for(c=[],l=new s.aes(r);c.length<f;)h(i),a=i.slice(0,i.length),v=l.encrypt(a),c=c.concat(v);return c=c.slice(0,f),o(e),u+=1,c}if(!(this instanceof v))throw new Error("create MsrcryptoPrng object with new keyword");var f=!1,r,i,e,n,u=1,y=16777216;return c(),{reseed:l,init:function(t,i){if(t.length<n)throw new Error("Initial entropy length too short");c();l(t,i);f=!0},getBytes:function(n,t){if(!f)throw new Error("can't get randomness before initialization");return a(n,t)},getNonZeroBytes:function(n,t){var r,u,i;if(!f)throw new Error("can't get randomness before initialization");for(r=[];r.length<n;)for(u=a(n,t),i=0;i<u.length;i+=1)u[i]!==0&&r.push(u[i]);return r.slice(0,n)}}}function nt(){function s(){for(var s=[],c,l,v,a,y,h=0;h<e;h+=1)s[h]=Math.floor(Math.random()*256);for(c=window.crypto||window.msCrypto,c&&typeof c.getRandomValues=="function"&&window.Uint8Array&&(l=new window.Uint8Array(e),c.getRandomValues(l),s=s.concat(Array.apply(null,l)),u=!0),v=new XMLHttpRequest,h=0;h<o.length;h+=1)try{a=v.getResponseHeader(o[h]);a&&(y=t.stringToBytes(a),s=s.concat(y))}catch(p){}u||(s=s.concat(n.splice(0,n.length)),f.startCollectors());r?i.reseed(s):i.init(s);r=!0}function h(t){for(var i=0;i<t.length;++i)n.push(t[i]);n.length>=c&&f.stopCollectors()}var e=48,n=[],c=128,l=0,i=new v,r=!1,u=!1,o=["Cookie","RedirectUri","ETag","x-ms-client-antiforgery-id","x-ms-client-request-id","x-ms-client-session-id","SubscriptionPool"],f=function(){return{startCollectors:function(){if(!this.collectorsRegistered){if(window.addEventListener)window.addEventListener("mousemove",this.MouseEventCallBack,!0),window.addEventListener("load",this.LoadTimeCallBack,!0);else if(document.attachEvent)document.attachEvent("onmousemove",this.MouseEventCallBack),document.attachEvent("onload",this.LoadTimeCallBack);else throw new Error("Can't attach events for entropy collection");this.collectorsRegistered=1}},stopCollectors:function(){this.collectorsRegistered&&(window.removeEventListener?(window.removeEventListener("mousemove",this.MouseEventCallBack,1),window.removeEventListener("load",this.LoadTimeCallBack,1)):window.detachEvent&&(window.detachEvent("onmousemove",this.MouseEventCallBack),window.detachEvent("onload",this.LoadTimeCallBack)),this.collectorsRegistered=0)},MouseEventCallBack:function(n){var t=(new Date).valueOf(),i=n.x||n.clientX||n.offsetX||0,r=n.y||n.clientY||n.offsetY||0,u=[t&255,t>>8&255,t>>16&255,t>>24&255,i&255,i>>8&255,r&255,r>>8&255];h(u)},LoadTimeCallBack:function(){var n=(new Date).valueOf(),t=[n&255,n>>8&255,n>>16&255,n>>24&255];h(t)}}}();return{init:function(){if(s(),!u&&!l)try{f.startCollectors()}catch(n){}},reseed:function(n){i.reseed(n)},read:function(n){if(!r)throw new Error("Entropy pool is not initialized.");var t=i.getBytes(n);return s(),t}}}var n={},a,r,s,c,u,i,o,p,h,f,b;n.register=function(t,i,r){n[t]||(n[t]={});var u=n[t];u[i]||(u[i]=r)};n.exists=function(t,i){return n[t]?n[t][i]?!0:!1:!1};var g=function(){if(typeof document!="undefined"){var n=document.getElementsByTagName("script");return n[n.length-1].src}return typeof self!="undefined"?self.location.href:null}(),tt=!1,w=typeof Worker!="undefined",l=typeof importScripts!="undefined",it=typeof Uint8Array!="undefined",rt=function(){try{return Object.defineProperty({},"oncomplete",{}),!0}catch(n){return!1}}(),e=w,ut=function(n){return Object.prototype.toString.call(n).replace("[object ","").replace("]","")},k=function(n,t,i,r,u){if(!rt){n[t]=i;return}var f={};r&&(f.get=r);u&&(f.set=u);Object.defineProperty(n,t,f)},d={},t=function(){function u(t,r){var f="",h,e,o,l,a,c,s,u;if(r||(r=!1),(t.pop||t.subarray)&&(t=String.fromCharCode.apply(null,t)),i)f=btoa(t);else for(u=0;u<t.length;u+=3)h=t.charCodeAt(u),e=t.charCodeAt(u+1),o=t.charCodeAt(u+2),l=h>>2,a=(h&3)<<4|e>>4,c=(e&15)<<2|o>>6,s=o&63,isNaN(e)?c=s=64:isNaN(o)&&(s=64),f=f+n.charAt(l)+n.charAt(a)+n.charAt(c)+n.charAt(s);return r?f.replace(/\+/g,"-").replace(/\//g,"_").replace(/\=/g,""):f}function f(n){if(i){for(n=n.replace(/-/g,"+").replace(/_/g,"/");n.length%4!=0;)n+="=";return atob(n)}return String.fromCharCode.apply(null,t(n))}function t(t){for(t=t.replace(/-/g,"+").replace(/_/g,"/");t.length%4!=0;)t+="=";var r=[],o,s,h,c,f,u,e,i;for(t=t.replace(/[^A-Za-z0-9\+\/\=]/g,""),i=0;i<t.length;i+=4)c=n.indexOf(t.charAt(i)),f=n.indexOf(t.charAt(i+1)),u=n.indexOf(t.charAt(i+2)),e=n.indexOf(t.charAt(i+3)),o=c<<2|f>>4,s=(f&15)<<4|u>>2,h=(u&3)<<6|e,r.push(o),u!==64&&r.push(s),e!==64&&r.push(h);return r}function e(n){return Object.prototype.toString.call(n).slice(8,-1)}function o(n,t){var r="",i,u;for(typeof t=="undefined"&&(t=!1),i=0;i<n.length;i++)t&&i%4==0&&i!==0&&(r+="-"),u=n[i].toString(16).toUpperCase(),u.length===1&&(r+="0"),r+=u;return r}function s(n){for(var i=new Array(n.length),t=0;t<i.length;t++)i[t]=n.charCodeAt(t);return i}function h(n){n=n.replace(/\-/g,"");for(var t=[];n.length>=2;)t.push(parseInt(n.substring(0,2),16)),n=n.substring(2,n.length);return t}function c(n){var i={};for(var t in n)n.hasOwnProperty(t)&&(i[t]=n[t]);return i}function l(n,i,r){var e=t(n),f=[],u;if(isNaN(i))return e;for(u=0;u<e.length;u+=i)f.push(e.slice(u,u+i));if(r)for(u=0;u<f.length;u++)f[u]=(f[u][0]<<24)+(f[u][1]<<16)+(f[u][2]<<8)+f[u][3];return f}function r(n){return[n>>>24&255,n>>>16&255,n>>>8&255,n&255]}function a(n){for(var t=[],i=0;i<n.length;i++)t=t.concat(r(n[i]));return t}function v(n,t){for(var r=Math.min(n.length,t.length),u=new Array(r),i=0;i<r;i+=1)u[i]=n[i]^t[i];return u}function y(n,t){var r,i;for(t||(t=0),r=new Array(n),i=0;i<n;i+=1)r[i]=t;return r}function p(n){if(n.pop)return n;if(n.length===1)return[n[0]];if(n.length<65536)return Array.apply(null,n);for(var r=new Array(n.length),i=0;i<n.length;i++)r[i]=n[i];return r}function w(n,t,i){if(n.indexOf)return n.indexOf(t,i);for(var r=i||0;r<n.length;r+=1)if(n[r]===t)return r;return-1}function b(n,t,i){while(n.length<i)n.push(t);return n}function k(n,t,i){while(n.length<i)n.unshift(t);return n}function d(n,t){if(n.length!==t.length)return!1;for(var i=0;i<n.length;i++)if(n[i]!==t[i])return!1;return!0}var n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",i=typeof btoa!="undefined";return{toBase64:u,base64ToString:f,base64ToBytes:t,getObjectType:e,bytesToHexString:o,stringToBytes:s,unpackData:l,hexToBytesArray:h,int32ToBytes:r,int32ArrayToBytes:a,indexOf:w,toArray:p,arraysEqual:d,clone:c,xorVectors:v,padEnd:b,padFront:k,getVector:y}}(),y=function(){function t(n){return l&&self.postMessage(n),n}return{jsCryptoRunner:function(i){var e=i.data.operationType,u,f,r;if(!n.exists(e,i.data.algorithm.name))throw new Error("unregistered algorithm.");return f=n[e][i.data.algorithm.name],r=i.data,r.operationSubType==="process"?(f(r),u=t({type:"process"})):u=t(f(r)),u}}}();return l&&(self.onmessage=function(n){if(n.data.prngSeed){var t=n.data.prngSeed;o.init(t);return}y.jsCryptoRunner(n)}),a=function(){function i(n){for(var t=[],i=0;i<n.length;i++)t[i]=n.charCodeAt(i);return t[t.length-1]===0&&t.pop(),t}function r(n){var t=n.algorithm.name.slice(0,3).toLowerCase();return t==="rsa"?"RSA":t==="ecd"?"EC":"oct"}function u(t,u){var f={},e,o;if(f.kty=r(t),f.extractable=t.extractable,u.pop)f.k=n.toBase64(u,!0);else for(e in u)u[e].pop&&(f[e]=n.toBase64(u[e],!0));return t.algorithm.namedCurve&&(f.crv=t.algorithm.namedCurve),o=JSON.stringify(f,null,"\t"),i(o)}function f(t,i,r){for(var e,o=String.fromCharCode.apply(null,t),f=JSON.parse(o),u=0;u<r.length;u+=1)e=f[r[u]],e&&(f[r[u]]=n.base64ToBytes(e));return f}var n=t;return{keyToJwk:u,jwkToKey:f}}(),r=function(){var r=function(n,t,i,r,u){function c(n){for(var nt=Math.floor(n.length/s),i,c,l,y,t,p,w,k,u,o,g,a,v,b,d=0;d<nt;d++){for(o=0;o<16;o++)b=d*s+o*4,e[o]=n[b]<<24|n[b+1]<<16|n[b+2]<<8|n[b+3];for(u=16;u<64;u++)v=e[u-15],a=e[u-2],e[u]=(a>>>17|a<<15)^(a>>>19|a<<13)^a>>>10,e[u]+=e[u-7],e[u]+=(v>>>7|v<<25)^(v>>>18|v<<14)^v>>>3,e[u]+=e[u-16];for(i=f[0],c=f[1],l=f[2],y=f[3],t=f[4],p=f[5],w=f[6],k=f[7],o=0;o<64;o++)g=k+((t>>>6|t<<26)^(t>>>11|t<<21)^(t>>>25|t<<7))+(t&p^~t&w)+r[o]+e[o],y+=g,g+=((i>>>2|i<<30)^(i>>>13|i<<19)^(i>>>22|i<<10))+(i&(c^l)^c&l),k=w,w=p,p=t,t=y,y=l,l=c,c=i,i=g;f[0]+=i&4294967295;f[1]+=c&4294967295;f[2]+=l&4294967295;f[3]+=y&4294967295;f[4]+=t&4294967295;f[5]+=p&4294967295;f[6]+=w&4294967295;f[7]+=k&4294967295}return h+=nt,n.slice(nt*s)}function v(){for(var t=new Array(256),n=0,i=0;n<8;n+=1,i+=4)t[i]=f[n]>>>24,t[i+1]=f[n]>>>16&255,t[i+2]=f[n]>>>8&255,t[i+3]=f[n]&255;return t.slice(0,u/8)}function y(n){var r=s-n.length,t,u,i;for(r<=8&&(r+=s),t=n.slice(),t.push(128),u=1;u<r-4;u++)t.push(0);return i=(n.length+h*s)*8,t.push(i>>>24&255),t.push(i>>>16&255),t.push(i>>>8&255),t.push(i&255),t}function l(n){return n.pop?n:n.length===1?[n[0]]:Array.apply(null,n)}function p(n){return o=c(l(n)),a()}function w(n){o=o.concat(l(n));o.length>=64&&(o=c(o));return}function a(){if(c(y(o)).length!==0)throw new Error("buffer.length !== 0");var n=v();return o=[],f=i.slice(),h=0,n}var s=64,f=i.slice(),e=new Array(s),o=[],h=0;return{name:n,computeHash:p,process:w,finish:a,der:t,hashLen:u,maxMessageSize:4294967295}},i,u,f,e,o,n=t.unpackData;return u=n("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q",4,1),f=n("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk",4,1),i=n("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g",4,1),e=n("MDEwDQYJYIZIAWUDBAIEBQAEIA"),o=n("MDEwDQYJYIZIAWUDBAIBBQAEIA"),{sha224:r("SHA-224",e,u,i,224),sha256:r("SHA-256",o,f,i,256)}}(),typeof n!="undefined"&&(r.hash256=function(n){if(n.operationSubType==="process"){r.sha256.process(n.buffer);return}return n.operationSubType==="finish"?r.sha256.finish():r.sha256.computeHash(n.buffer)},r.hash224=function(n){if(n.operationSubType==="process"){r.sha224.process(n.buffer);return}return n.operationSubType==="finish"?r.sha224.finish():r.sha224.computeHash(n.buffer)},n.register("digest","sha-224",r.hash224),n.register("digest","sha-256",r.hash256)),d["sha-224"]=r.sha224,d["sha-256"]=r.sha256,s=function(){var o,n,i,r,u,f,e,s,h,c;return{aes:function(l){var d,b,a,p,v,y;o||(o=t.unpackData("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v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN",256,!1),n=o[0],i=o[1],r=o[2],u=o[3],f=o[4],e=o[5],s=o[6],h=o[7],c=o[8]);d=128;p=4;switch(l.length*8){case 128:b=128;a=4;v=10;break;case 192:b=192;a=6;v=12;break;case 256:b=256;a=8;v=14;break;default:throw new Error("Unsupported keyLength");}var g=function(n){var t=n[1];n[1]=n[5];n[5]=n[9];n[9]=n[13];n[13]=t;t=n[2];n[2]=n[10];n[10]=t;t=n[6];n[6]=n[14];n[14]=t;t=n[15];n[15]=n[11];n[11]=n[7];n[7]=n[3];n[3]=t},nt=function(n){var t=n[13];n[13]=n[9];n[9]=n[5];n[5]=n[1];n[1]=t;t=n[10];n[10]=n[2];n[2]=t;t=n[14];n[14]=n[6];n[6]=t;t=n[3];n[3]=n[7];n[7]=n[11];n[11]=n[15];n[15]=t},ut=function(t){var r=t[0],u=t[1],f=t[2],e=t[3],o=t[4],s=t[5],h=t[6],c=t[7],l=t[8],a=t[9],v=t[10],y=t[11],p=t[12],w=t[13],b=t[14],k=t[15];t[0]=n[r]^i[u]^f^e;t[1]=r^n[u]^i[f]^e;t[2]=r^u^n[f]^i[e];t[3]=i[r]^u^f^n[e];t[4]=n[o]^i[s]^h^c;t[5]=o^n[s]^i[h]^c;t[6]=o^s^n[h]^i[c];t[7]=i[o]^s^h^n[c];t[8]=n[l]^i[a]^v^y;t[9]=l^n[a]^i[v]^y;t[10]=l^a^n[v]^i[y];t[11]=i[l]^a^v^n[y];t[12]=n[p]^i[w]^b^k;t[13]=p^n[w]^i[b]^k;t[14]=p^w^n[b]^i[k];t[15]=i[p]^w^b^n[k]},ft=function(n){var t=n[0],i=n[1],o=n[2],s=n[3],h=n[4],c=n[5],l=n[6],a=n[7],v=n[8],y=n[9],p=n[10],w=n[11],b=n[12],k=n[13],d=n[14],g=n[15];n[0]=r[t]^f[i]^u[o]^e[s];n[1]=e[t]^r[i]^f[o]^u[s];n[2]=u[t]^e[i]^r[o]^f[s];n[3]=f[t]^u[i]^e[o]^r[s];n[4]=r[h]^f[c]^u[l]^e[a];n[5]=e[h]^r[c]^f[l]^u[a];n[6]=u[h]^e[c]^r[l]^f[a];n[7]=f[h]^u[c]^e[l]^r[a];n[8]=r[v]^f[y]^u[p]^e[w];n[9]=e[v]^r[y]^f[p]^u[w];n[10]=u[v]^e[y]^r[p]^f[w];n[11]=f[v]^u[y]^e[p]^r[w];n[12]=r[b]^f[k]^u[d]^e[g];n[13]=e[b]^r[k]^f[d]^u[g];n[14]=u[b]^e[k]^r[d]^f[g];n[15]=f[b]^u[k]^e[d]^r[g]},tt=function(n,t){return[n[0]^t[0],n[1]^t[1],n[2]^t[2],n[3]^t[3]]},w=function(n,t,i){for(var r=0;r<n.length;r+=1)n[r]^=t[r+i]},et=function(n){var t=n[0];n[0]=n[1];n[1]=n[2];n[2]=n[3];n[3]=t},k=function(n){for(var t=0;t<n.length;t+=1)n[t]=s[n[t]]},it=function(n){for(var t=0;t<n.length;t+=1)n[t]=h[n[t]]},rt=function(n,t){return[n[4*t],n[4*t+1],n[4*t+2],n[4*t+3]]},ot=function(n,t,i,r){n[4*i]=t[4*r];n[4*i+1]=t[4*r+1];n[4*i+2]=t[4*r+2];n[4*i+3]=t[4*r+3]},st=function(n){for(var i,r=[],t=0,u,f,e;t<4*a;)r.push(n[t++]);for(t=a;t<p*(v+1);)i=rt(r,t-1),t%a==0?(u=t/a,f=[c[u],0,0,0],et(i),k(i),i=tt(i,f)):a>6&&t%a==4&&k(i),e=tt(rt(r,t-a),i),ot(r,e,t,0),t+=1;return r};return y=st(l),{encrypt:function(n){var t=n,i;for(w(t,y,0),i=1;i<=v-1;i+=1)k(t),g(t),ut(t),w(t,y,4*i*p);return k(t),g(t),w(t,y,4*v*p),t},decrypt:function(n){var t=n,i;for(w(t,y,4*v*p),i=v-1;i>=1;i-=1)nt(t),it(t),w(t,y,4*i*p),ft(t);return nt(t),it(t),w(t,y,0),t},clear:function(){},keyLength:b,blockSize:d}}}}(),c=c||{},c.pkcsv7=function(n,t){var o=n.length-1>=0?n.length-1:0,i=n[o],f=i.length,s=f===t,r,u,e;if(s){for(r=[],u=0;u<t;u+=1)r.push(t);n.push(r)}else for(e=t-f&255;i.length!==t;)i.push(e)},u=function(n){function o(n){var f=[],r,t;for(i=i.concat(n),r=Math.floor(i.length/u),t=0;t<r;t++)f.push(i.slice(t*u,(t+1)*u));return i=i.slice(r*u),f}function s(i){for(var u=[],e,r=0;r<i.length;r++)e=t.xorVectors(f,i[r]),u.push(n.encrypt(e)),f=u[r];return u}function a(i){for(var u=[],e,o,r=0;r<i.length;r+=1)e=i[r].slice(0,i[r].length),o=n.decrypt(e),u.push(t.xorVectors(f,o)),f=i[r];return u}function h(){i=[];r=[];f=null}var u=n.blockSize/8,l=c.pkcsv7,e=function(n){for(var u=[],i,r,t=0;t<n.length;t+=1)for(r=n[t],i=0;i<r.length;i+=1)u.push(r[i]);return u},i=[],r=[],f;return{init:function(n){if(n.length!==u)throw new Error("Invalid iv size");f=n.slice()},encrypt:function(n){return this.processEncrypt(n),this.finishEncrypt()},processEncrypt:function(n){var t=s(o(n));r=r.concat(e(t));return},finishEncrypt:function(){var n=i.length===1?[[i[0]]]:[i],t;return l(n,u),t=r.concat(e(s(n))),h(),t},decrypt:function(n){return this.processDecrypt(n),this.finishDecrypt()},processDecrypt:function(n){var t=a(o(n));r=r.concat(e(t));return},finishDecrypt:function(){var n=r;return n=n.slice(0,n[n.length-1]*-1),h(),n}}},i=null,typeof n!="undefined"&&(u.workerEncrypt=function(n){var t;if(i||(i=u(s.aes(n.keyData)),i.init(n.algorithm.iv)),n.operationSubType==="process"){i.processEncrypt(n.buffer);return}return n.operationSubType==="finish"?(t=i.finishEncrypt(),i=null,t):(t=i.encrypt(n.buffer),i=null,t)},u.workerDecrypt=function(n){var t;if(i||(i=u(s.aes(n.keyData)),i.init(n.algorithm.iv)),n.operationSubType==="process"){i.processDecrypt(n.buffer);return}return n.operationSubType==="finish"?(t=i.finishDecrypt(),i=null,t):(t=i.decrypt(n.buffer),i=null,t)},u.generateKey=function(n){if(n.algorithm.length%8!=0)throw new Error;return{type:"keyGeneration",keyData:o.getBytes(Math.floor(n.algorithm.length/8)),keyHandle:{algorithm:n.algorithm,extractable:n.extractable,keyUsage:null||n.keyUsage,type:"secret"}}},u.importKey=function(n){var t=a.jwkToKey(n.keyData,n.algorithm,["k"]);return{type:"keyImport",keyData:t.k,keyHandle:{algorithm:n.algorithm,extractable:n.extractable||t.extractable,keyUsage:null||n.keyUsage,type:"secret"}}},u.exportKey=function(n){var t=a.keyToJwk(n.keyHandle,n.keyData);return{type:"keyExport",keyHandle:t}},n.register("importKey","aes-cbc",u.importKey),n.register("exportKey","aes-cbc",u.exportKey),n.register("generateKey","aes-cbc",u.generateKey),n.register("encrypt","aes-cbc",u.workerEncrypt),n.register("decrypt","aes-cbc",u.workerDecrypt)),o=new v,l||(p=function(){function h(){function t(t){try{if(n=y.jsCryptoRunner({data:t}),!t.operationSubType||t.operationSubType!=="process")this.onmessage({data:n})}catch(i){this.onerror({data:i.description,type:"error"})}}var n;return{postMessage:t,onmessage:null,onerror:null,terminate:function(){}}}function c(n){function u(){}function f(){}function e(n){i=n;this.result&&i({target:this})}function o(n){r=n}function s(){return i}function h(){return r}function c(t){if(t.type==="error"){if(this.onerror)this.onerror(t);return}if(t.type!=="process"){if(this.result=n(t.data),this.oncomplete)this.oncomplete({target:this});return}}var i=null,r=null,t;return t={dispatchEvent:c,addEventListener:u,removeEventListener:f,result:null},k(t,"oncomplete",null,s,e),k(t,"onerror",null,h,o),t}function tt(){function n(n){switch(n.type){case"keyGeneration":case"keyImport":case"keyDerive":return i.add(n.keyHandle,n.keyData),n.keyHandle;case"keyExport":return p(n.keyHandle);case"keyPairGeneration":return i.add(n.keyPair.publicKey.keyHandle,n.keyPair.publicKey.keyData),i.add(n.keyPair.privateKey.keyHandle,n.keyPair.privateKey.keyData),{publicKey:n.keyPair.publicKey.keyHandle,privateKey:n.keyPair.privateKey.keyHandle};default:throw new Error("Unknown key operation");}return}return c(n)}function rt(n){function i(n){return p(n)}var t=c(i);return t.process=function(t){n.operationSubType="process";n.buffer=u.toArray(t);f.continueJob(this,u.clone(n))},t.finish=function(){n.operationSubType="finish";n.buffer=[];f.continueJob(this,u.clone(n))},t.abort=function(){f.abortJob(this)},t.onabort=null,t.onprogress=null,t.algorithm=n.algorithm||null,t.key=n.keyHandle||null,t}function p(n){return it&&n.pop?new Uint8Array(n).buffer:n}function ft(n){if(n.oncomplete)n.oncomplete({target:n});else setTimeout(function(){ft(n)},b)}function d(t,i){if(!n.exists(t,i))throw new Error("unsupported algorithm");}function v(n){var t=i.lookup(n);if(!t)throw new Error("key not found");return t}function nt(n,t){for(var r,i,e={operationType:n},o=a[n],f=0;f<o.length;f+=1){if(r=l[o[f]],i=t[f],!i)if(r.required)throw new Error(r.name);else continue;if(i.subarray&&(i=u.toArray(i)),ut(i)!==r.type)throw new Error(r.name);r.name==="algorithm"&&(i.name=i.name.toLowerCase(),i.iv&&(i.iv=u.toArray(i.iv)),i.additionalData&&(i.additionalData=u.toArray(i.additionalData)));e[r.name]=i}return e}function r(n,t,i){var r=nt(n,t),u;return d(n,r.algorithm.name),r.keyHandle&&(r.keyData=v(r.keyHandle)),r.algorithm&&r.algorithm.publicKey&&(r.additionalKeyData=v(r.algorithm.publicKey)),u=i?tt(r):rt(r),(i||r.buffer||n==="deriveBits")&&f.runJob(u,r),u}var b=100,i=[],f,u,l,a,s;return i.add=function(n,t){i.push({keyHandle:n,keyData:t})},i.remove=function(n){for(var t=0;t<i.length;t++)if(i[t].keyHandle===n){i=i.splice(t,1);return}},i.lookup=function(n){for(var t=0;t<i.length;t++)if(i[t].keyHandle===n)return i[t].keyData;return null},f=function(){function b(){k(!e);for(var t=0;t<n.length;t++)if(!n[t].busy)return n[t];return null}function k(t){for(var i=n.length-1;i>=0;i-=1)n[i].isWebWorker===t&&(n[i].terminate(),n.splice(i,1))}function d(){for(var i=0,t=0;t<n.length;t++)n[t].busy||(i+=1);return i}function nt(t){n.push(t)}function r(t){for(var i=0;i<n.length;i++)if(n[i]===t){t.terminate();n.splice(i,1);return}}function u(t){for(var i=0;i<n.length;i++)if(n[i].operation===t)return n[i];return null}function f(n,i){t.push({operation:n,data:i,id:p++})}function c(n){if(n.busy=!1,n.operation=null,e)if(t.length>0){var i=t.shift();a(i.operation,i.data)}else d()>y&&r(n)}function tt(n){var r;if(e)try{r=new Worker(g);r.postMessage({prngSeed:o.getBytes(48)});r.isWebWorker=!0}catch(u){e=!1;s.forceSync=!0;r=h();r.isWebWorker=!1}else r=h(),r.isWebWorker=!1;return r.operation=n,r.busy=!1,r.onmessage=function(n){for(var e,f=r.operation,u=0;u<t.length;u++)if(t[u].operation===r.operation){e=t[u];t.splice(u,1);i(r,e.data);return}f&&n.data.type!=="process"&&(c(r),f.dispatchEvent(n))},r.onerror=function(n){var t=r.operation;c(r);t.dispatchEvent(n)},nt(r),r}function it(n){var t=u(n);t&&r(t)}function l(t,r){var u=null;if(e=w&&!s.forceSync,u=b(),e&&u===null&&n.length>=v){f(t,r);return}if(u===null&&(u=tt(t)),u===null){f(t,r);throw new Error("could not create new worker");}u.operation=t;u.busy=!0;i(u,r)}function a(n,t){var r=u(n);if(r){i(r,t);return}l(n,t)}function i(n,t){e?(n.data=t,n.postMessage(t)):setTimeout(function(){n.postMessage(t)},0)}var v=15,y=4,n=[],t=[],p=0;return{runJob:l,continueJob:a,abortJob:it}}(),u=t,l=[{name:"algorithm",type:"Object",required:!0},{name:"keyHandle",type:"Object",required:!0},{name:"buffer",type:"Array",required:!1},{name:"signature",type:"Array",required:!0},{name:"format",type:"String",required:!0},{name:"keyData",type:"Array",required:!0},{name:"extractable",type:"Boolean",required:!1},{name:"keyUsages",type:"Array",required:!1},{name:"derivedKeyType",type:"Object",required:!0},{name:"length",type:"Number",required:!1}],a={encrypt:[0,1,2],decrypt:[0,1,2],sign:[0,1,2],verify:[0,1,3,2],digest:[0,2],generateKey:[0,6,7],importKey:[4,5,0,6,7],exportKey:[0,4,1,6,7],deriveKey:[0,1,8,6,7],deriveBits:[0,1,9]},s={encrypt:function(){return r("encrypt",arguments,0)},decrypt:function(){return r("decrypt",arguments,0)},sign:function(){return r("sign",arguments,0)},verify:function(){return r("verify",arguments,0)},digest:function(){return r("digest",arguments,0)},generateKey:function(){return r("generateKey",arguments,1)},deriveKey:function(){return r("deriveKey",arguments,1)},deriveBits:function(){return r("deriveBits",arguments,0)},importKey:function(){return r("importKey",arguments,1)},exportKey:function(n,t){return r("exportKey",[t.algorithm,n,t],1)},wrapKey:function(){throw new Error("not implemented");},unwrapKey:function(){throw new Error("not implemented");}}}()),h={subtle:p,getRandomValues:function(n){for(var i=o.getBytes(n.length),t=0;t<n.length;t+=1)n[t]=i[t];return n},initPrng:function(n){var t=Object.prototype.toString.call(n);if(t!=="[object Array]"&&t!=="[object Uint8Array]")throw new Error("entropyData must be a Array or Uint8Array");f&&f.reseed(n);o.reseed(f.read(48));tt=!0},stringToBase64:t.toBase64,base64ToString:t.base64ToString},typeof cryptoMath!="undefined"&&(h.cryptoMath=cryptoMath),typeof testInterface!="undefined"&&(h.testInterface=testInterface),l||(f=f||new nt,f.init(),b=f.read(48),o.init(b)),h}();
window.scriptsLoaded['msrcrypto-aes.js'] = 1; window.scriptProcessEnd = window.scriptProcessEnd || {}; window.scriptProcessEnd['msrcrypto-aes.js'] = (new Date()).getTime();