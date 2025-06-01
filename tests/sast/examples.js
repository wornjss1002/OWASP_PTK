// js/document_write.js

// sink
function runSink(input) {
    document.write('<div id="out">' + input + '</div>');
}

// helper to read our cookie
function getCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
}

let a = getCookie('name')
runSink(a)

let b = document.cookie
runSink(b)



var stores = ["London", "Paris", "Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if (store) {
    document.write('<option selected>' + store + '</option>');
}
for (var i = 0; i < stores.length; i++) {
    if (stores[i] === store) {
        continue;
    }
    document.write('<option>' + stores[i] + '</option>');
}
document.write('</select>');


document.write('safe');



let c1= location.search
document.cookie = c1



function getCookie_1(cname) {
  var name = cname + "=";
  var decodedCookie = decodeURIComponent(document.cookie);
  var ca = decodedCookie.split(';');
  for(var i = 0; i <ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

let msg = "window.name: <b>" + getCookie_1("userName") + "</b>";
document.getElementById("output").innerHTML = msg;


let html = `<p>Welcome ${getCookie('test')}</p>`;
container.innerHTML = html;