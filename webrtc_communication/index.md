# 基于局域网的音视频即时聊天客户端及服务器软件设计与开发


{{< admonition type=warning title="" open=false >}}
此项目成员均为学生，还在开发过程中，因此相比企业级项目而言页面简陋技术落后，望看到这篇文章的高手轻喷。并且如果发现BUG或有改进建议，欢迎和我联系！
{{< /admonition >}}

> ## 摘要
本课题拟重点关注应急通信的需求，在临时搭建的局域网通信环境下，设计与开发适用于手机、平板和电脑的音视频即时聊天工具，包括客户端和服务器软件，实现无互联网环境下的局域网即时通信功能。

以下是本课题所用到的技术：

- HTML
- CSS
- Javascript
- Electron
- Cordova
- nodejs

Github源代码：

> ## 模块介绍

> ### 主服务器端

> #### 前端

前端页面的设计包括HTML+CSS的网页展示模块以及基于JavaScript前端脚本模块。  
其中，前端脚本模块所做的工作如下：

1. 利用DOM操作获取到网页中输入框的内容，并进行初步的模式匹配，以防止不合法的输入出现。
2. 利用Ajax机制进行前后端数据通信，通过访问后端服务器所提供的接口URL来进行相关的注册、登录、信息修改以及网页跳转的工作。
3. 在获得了后端服务器发来的成功登录的信息后，将报文中的token保存在浏览器本地的sessionStorage中，并在后续的每次访问中携带该token。

> #### 后端

后端需要引入数据库模块用于记录用户的注册信息。在本项目中使用了MySQL关系型数据库，用过JavaScript操作SQL语句进行数据的增、删、查、改操作。  
服务器对外提供了登录、注册、用户信息修改的接口，以登录接口为例，登录接口的URL地址如下：http://服务器IP:服务端口号/api/login  
后端提供登录、注册、信息增删的服务之前需要采取如下操作：

1. 利用开源的joi模块进行前端所发来的数据的模式识别，以防止不合法的输入被传入数据库。
2. 若因为注册、信息修改等操作导致用户密码被设置或修改，需要利用开源的bscryptjs模块对密码进行加密后再写入数据库，以防止泄密。在每次登录时，需要将从数据库中取出的密码解密后再与前端所发来的密码比对。
3. 在验证用户信息后，主服务器会依据从数据库中获取到的用户信息，利用开源的jsonwebtoken模块生成一个JSON格式的token串，并将该token串以及相应的信息传输给前端，随后前端的每次带权限的请求（如获取WebRTC即时音视频服务、访问主页等）都需要携带此token，后端验证token通过后才提供相应的服务。
此外，服务器需要将前端页面所需要的所有HTML以及相关的CSS样式、JavaScript脚本文件设置成静态资源以方面用户进行访问。

> ### 信令服务器端

> #### WebRTC开发环境搭建

WebRTC目前已经被Trident、Chromium、Webkit等多种浏览器内核所支持，具有很高的兼容性，不需要额外的下载外部模块。但是，如表4-1所示，由于不同厂商在开发WebRTC项目时对同一个接口采用了不同的接口名，不同的浏览器在运行同一个WebRTC应用时可能会出现接口不适配的问题。
| WebRTC标准 |	Chrome |	Firefox |
| ------------ | --- | ------------- | 
| getUserMedia |	webkitGetUserMedia |	getUserMedia |
| RTCPeerConnection |	webkitRTCPeerConnection |	RTCPeerConnection |
| RTCsessionDescription |	RTCsessionDescription |	RTCsessionDescription |
| RTCIceCandidate |	RTCIceCandidate|	RTCIceCandidate |


因此，需要采用WebRTC官方提供的适配器adapter-latest.js文件才能解决如上的兼容性问题。该兼容性解决方案需要在渲染页面时引入，即在即时通话的HTML页面中使用`<script src="adapter-latest.js"></script>`语句引入适配器文件。

![process1](/images/process1.png)

> #### 信令服务器端

1. 服务器使用app.use(express.static(path.join(__dirname, '../public')))语句将对外提供的HTML、CSS以及JavaScript脚本文件设置为静态资源，客户端可以通过URL来访问这些资源以获取即时通信服务。其中，app为信令服务器所创建的HTTPS服务器实例，‘public’为存放客户端文件的目录。

2. 服务器在获取到客户端的URL后，根据URL中携带的jwt token字符进行身份校验，若token验证通过才将URL对应的资源页面提供给客户端，否则，拒绝这次请求。

3. 使用socket.io技术实时监听客户端所发来的数据，以协助通信双方的信令交互。
服务器的处理流程如下图所示：

 <img src='/images/process2.jpg' width='60%' >

> #### 浏览器前端

浏览器前端的所需要完成功能则相对较多，包括获取音视频流、协商通信配置、建立P2P连接等，按照顺序可以分为以下几个步骤：
1. 获取客户端本地的音视频流
由于针对不同的客户端以及浏览器会有不同的硬件设备，需要为这些不同的设备或浏览器提供兼容性的解决方案，因此需要引入由WebRTC官方提供的适配器模块
adapter.js。随后通过getUserMedia函数获取音视频流。

2. 建立PeerConnection对象
在客户端的JavaScript脚本内创建PeerConnection，由于创建、协调并维持通信双方的连接。随后，将PeerConnection的ontrack成员方法与远程视频流绑定，将
PeerConnection的addStream成员方法与本地视频流绑定。

3. 加入房间
在访问即时音视频通信服务中，会在get请求中附带room参数，在成功获取到服务后，前端会向信令服务器使用socket.io的emit函数发送一个名为rooms的事件，事
件携带的数据为get请求中room的参数。  
服务器监听到rooms事件后，会将该客户加入值为room的房间，随后，该客户的所有信令信息仅在值为room的房间中转发。

4. 协商会话描述配置
受限于通信双方的硬件设置等因素的影响，在正式通信之前通信双方需要协商通信的配置信息。主叫向被叫发送PeerConnection的成员变量 localDescription，被
叫通过使用PeerConnection的成员方法setRemoteDescription来实现主叫与被叫之间的会话描述配置。  
客户端通过socket.io的emit函数发送一个名为message的事件，事件携带的参数为localDescription。

5. 协商连接双方的网络信息
由于通信双方可能处于NAT网络之后，需要通过ICE服务器提供的内网穿透服务才能正式建立连接，因此通信双方之间需要发送RTCIceCandidate这一对象，该对象包
含的属性包括本地IP地址、公网IP地址等等所有相关网络配置信息。  
该配置信息的发送是基于socke.io发送的名为message的事件来实现。

6. 建立P2P连接
主叫通过调用PeerConnection的成员方法createOffer向被叫发起建立连接请求，被叫收到请求后可以拒绝这个请求或调用PeerConnection的成员方法createAnswer
来响应这个请求。  
主叫与被叫所发送的信息都是基于socket.io的emit函数来发送一个名为message的事件。

> ### 移动端

由于项目基于web开发，所以选择cordova框架进行打包移植。打包的流程大致如下：

1. 相关的环境配置

2. 创造cordova项目

3. 在项目中添加移动端平台

4. 将前端页面文件移入www文件夹

5. 将页面布局调整以适应手机大小

6. 在config.xml中修改权限解决跨域问题

7. 生成app

8. 后续实机调试

> ## 核心代码

> ### 注册和登录

> #### 前端
为按钮绑定ajax事件将用户输入的信息传到后端，根据后端返回信息决定下一步。
```Javascript
const ip = '192.168.101.108';
let login_btn = document.getElementById('login_btn');
let id = document.getElementById('id');
let password = document.getElementById('password');
$('#login_btn').on('click', function () {
    var params = 'id=' + id.value + '&password=' + password.value;
    console.log("clicked login")
    $.ajax({
        type: 'post',
        url: 'http://' + ip + ':3007/api/login',
        contentType: 'application/x-www-form-urlencoded',
        data: params,
        success: function (result) {
            window.localStorage.setItem(result.id, result.id);
            sessionStorage.name = result.name;
            sessionStorage.id = result.id;
            sessionStorage.serverIP = result.serverIP;
            if (result.status === 0) {
                alert("登录成功,跳转至主界面");
                window.location.href = "./HomePage.html";
            }
            else
                alert(result.message);
        }
    })
})
let register = document.getElementById('register');
let Rid = document.getElementById('Rid');
let Rname = document.getElementById('Rname');
let Rpassword = document.getElementById('Rpassword');
$('#register').on('click',function () {
    var params = "id=" + Rid.value + "&password=" + Rpassword.value + "&name=" + Rname.value;
    console.log(params)
    console.log('http://' + ip + ':3007/api/reguser')
    $.ajax({
        type: 'post',
        url: 'http://' + ip + ':3007/api/reguser',
        contentType: 'application/x-www-form-urlencoded',
        data: params,
    }).then(result => {
        if (result.status === 0) {
            alert("注册成功,点击回到登陆界面");
            window.location.reload()
        }
        else {
            alert(result.message);  
        }
    })
    .catch(err=>{
        console.log("failure:",err)
        alert('something wrong')
    })
})

```

> #### 后端
在数据库中检索用户输入信息并执行相关操作
```Javascript
exports.regUser = (req, res) => {
  // 获取客户端提交到服务器的用户信息
  const userinfo = req.body;

  // 定义 SQL 语句，查询用户名是否被占用
  const sqlStr = 'select * from users where id=?';
  db.query(sqlStr, userinfo.id, (err, results) => {
    // 执行 SQL 语句失败
    if (err) {
      return res.cc(err);
    }
    // 判断用户名是否被占用
    if (results.length > 0) {
      return res.cc('用户名被占用，请更换其他用户名！', 2);
    }
    // 调用 bcrypt.hashSync() 对密码进行加密
    userinfo.password = bcrypt.hashSync(userinfo.password, 10);

    // 定义插入新用户的 SQL 语句
    const sql = 'insert into users set ?';
    // 调用 db.query() 执行 SQL 语句
    db.query(sql, { id: userinfo.id, password: userinfo.password, name: userinfo.name }, (err, results) => {
      // 判断 SQL 语句是否执行成功
      // if (err) return res.send({ status: 1, message: err.message })
      if (err) return res.cc(err);
      // 判断影响行数是否为 1
      if (results.affectedRows !== 1) return res.cc('注册用户失败，请稍后再试！', 1);
      // 注册用户成功
      res.cc('注册成功！', 0, 'http://' + ip + ':3007');
    })
  })
}

// 登录的处理函数
exports.login = (req, res) => {
  console.log("login post received!")
  const userinfo = req.body;
  console.log(userinfo)
  const sql = 'select * from users where id = ?';
  db.query(sql, userinfo.id, (err, results) => {
    if (err) {
      console.log("error!")
      return res.cc(err);
    }
    if (results.length !== 1) return res.cc('登陆失败');

    //比较密码是否正确
    const compare = bcrypt.compareSync(userinfo.password, results[0].password);
    if (!compare) return res.cc('密码输入错误');
    //else return res.cc('登陆成功', 0);

    const user = { ...results[0], password: '', user_pic: '' };//...为展开运算符，将results[0]中所有元素赋给user
    //利用用户信息生成token
    const token = jwttoken.sign(user, jwtconfig.jwtSecretKey, { expiresIn: jwtconfig.expiresIn });//有效期为3小时
    res.send({
      status: 0,
      message: '登陆成功！',
      token: 'Bearer ' + token,
      url: 'http://' + ip + ':3007/HomePage.html',
      name: results[0].name,
      id: results[0].id,
      serverIP: ip
    })
  })
}

```

> ### 用户界面
通过socket实现用户列表的显示和更新
> #### 前端
```Javascript
socket.on("connect", () => {
    sessionStorage.socketID = socket.id;
    socket.emit('login', JSON.stringify({ 'id': sessionStorage.id, 'name': sessionStorage.name, 'sid': sessionStorage.socketID }));
});

socket.on('called', (data) => {
    var info = JSON.parse(data);
    console.log('this is info inside called:',info)
    if (info.calledID == sessionStorage.id) {
    console.log('Woops,it seems you are being called!')
    window.blur(); setTimeout(window.focus(), 100);
    var r = window.confirm('您正在被' + info.callingID + '呼叫！');
    if (r == false) {
        socket.emit('refuse', JSON.stringify({ 'name': sessionStorage.name, 'callingSid': info.callingSid }));
    }
    else {
        // window.open('https://' + sessionStorage.serverIP + ':8443/index.html?room=' + info.callingID+'&id='+sessionStorage.id);
        socket.emit('agree', info.callingSid);
        window.location.href='https://' + sessionStorage.serverIP + ':8443/index.html?room=' + info.callingID+'&id='+sessionStorage.id;
    }
    }
})

socket.on('refuse', (data) => {
    alert(data + '拒绝了您的通话请求！');
});

socket.on('agree', () => {
    console.log(1);
    
    // window.open('https://' + sessionStorage.serverIP + ':8443/index.html?room=' + sessionStorage.id+'&id='+sessionStorage.id);
    console.log('your invitation has been accepted!')
    window.location.href='https://' + sessionStorage.serverIP + ':8443/index.html?room=' + sessionStorage.id+'&id='+sessionStorage.id;
})
const socket = io(sessionStorage.serverIP + ':3007');
var table = document.getElementById('table');

socket.on('init', data => {
    for (var i = 0; i < data.length; i++) {
        if (data[i].id != sessionStorage.id) {
            var tr = document.createElement('tr');
            table.appendChild(tr);
            //创建Sid栏
            var td_sid = document.createElement('td');
            td_sid.innerHTML = data[i].sid;
            tr.appendChild(td_sid);
            //创建id栏
            var td_id = document.createElement('td');
            td_id.innerHTML = data[i].id;
            td_id.id = data[i].id;
            tr.appendChild(td_id);
            //创建name栏
            var td_name = document.createElement('td');
            td_name.innerHTML = data[i].name;
            tr.appendChild(td_name);
            //创建会话图标栏
            var td_RTC = document.createElement('td');
            //创建图标
            var button = document.createElement('button');
            button.addEventListener('click', () => {
                var data = JSON.stringify({ 'callingID': sessionStorage.id, 'calledID': td_id.id, 'callingSid': sessionStorage.socketID });
                socket.emit('calling', data);
            });
            var img = document.createElement('img');
            img.setAttribute('src', '../assets/images/camera.webp');
            img.setAttribute('height', '30px');
            button.appendChild(img);
            tr.appendChild(button);
        }
    }
})

socket.on('online', (data) => {
    var user = JSON.parse(data);
    if (user.id != sessionStorage.id) {
        //动态创建行
        var tr = document.createElement('tr');
        table.appendChild(tr);
        //创建Sid栏
        var td_sid = document.createElement('td');
        td_sid.innerHTML = user.sid;
        tr.appendChild(td_sid);
        //创建id栏
        var td_id = document.createElement('td');
        td_id.innerHTML = user.id;
        td_id.id = user.id;
        tr.appendChild(td_id);
        //创建name栏
        var td_name = document.createElement('td');
        td_name.innerHTML = user.name;
        tr.appendChild(td_name);
        //创建会话图标栏
        var td_RTC = document.createElement('td');
        //创建图标
        var button = document.createElement('button');
        button.addEventListener('click', () => {
            var data = JSON.stringify({ 'callingID': sessionStorage.id, 'calledID': td_id.id, 'callingSid': sessionStorage.socketID });
            socket.emit('calling', data);
        });
        var img = document.createElement('img');
        img.setAttribute('src', '../assets/images/camera.webp');
        img.setAttribute('height', '30px');
        button.appendChild(img);
        tr.appendChild(button);
    }
});

socket.on('offline', (data) => {
    const table = document.getElementById('table');
    for (var i = 1; i < table.rows.length; i++) {
        //console.log(table.rows[i].cells[0].innerHTML);
        if (table.rows[i].cells[0].innerHTML == data)
            table.deleteRow(i);
    }
});
```

> #### 后端

```Javascript
const { Server } = require("socket.io");
const io = new Server(httpServer, {
  cors: {
    origin: "*",
  }
});
io.on('connect', (socket) => {
  console.log(socket.id)
  io.to(socket.id).emit('init', L.toArray(l));
  socket.on('login', (data) => {
    const info = JSON.parse(data);
    console.log(info)
    l = L.append({ 'sid': info.sid, 'id': info.id, 'name': info.name }, l);//当io监听到有人登录 将sid、id和名字添加到list
    io.emit('online', data);
  })

  socket.on('disconnect', () => {
    io.emit('offline', socket.id);
    var a = L.toArray(l);
    for (var i = 0; i < a.length; i++) {  //监听到有人退出，从列表中把推出的用户信息删除
      if (a[i].sid === socket.id) {
        l = L.remove(i, 1, l);
        return;
      }
    }
  })

  socket.on('calling', (data) => {
    console.log('calling socket req received!',data)
    io.emit('called', data);
  });

  socket.on('refuse', (data) => {
    var info = JSON.parse(data);
    io.to(info.callingSid).emit('refuse', info.name); //
  });

  socket.on('agree', callingSid => {
    console.log(callingSid+`'s invitation has been accepted!`);
    io.to(callingSid).emit('agree');
  })
})
```

> ### 通话页面

> #### 前端

```Javascript
var localVideo;
var localStream;
var remoteVideo;
//用于WebRTC连接的类
var peerConnection;
var uuid;



//配置ice服务器
var peerConnectionConfig = {
    'iceServers': [
        { 'urls': 'stun:stun.stunprotocol.org:3478' },
        { 'urls': 'stun:stun.l.google.com:19302' },
    ]
};

function pageReady() {
    uuid = createUUID();
    console.log('this is uuid:',uuid);
    localVideo = document.getElementById('localVideo');
    remoteVideo = document.getElementById('remoteVideo');

    socket.on('message', (message) => {

        if (!peerConnection) start(false);

        var signal = JSON.parse(message);
        // Ignore messages from ourself
        if (signal.uuid == uuid) return;
        console.log(`this is signal.uuid:${signal.uuid}`);
        if (signal.sdp) {
            peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp)).then(function () {
                // Only create answers in response to offers
                if (signal.sdp.type == 'offer') {
                    //如果收到的消息类型是offer请求，则创建一个响应来建立视频会话
                    peerConnection.createAnswer().then(createdDescription).catch(errorHandler);
                }
            }).catch(errorHandler);
        } else if (signal.ice) {
            peerConnection.addIceCandidate(new RTCIceCandidate(signal.ice)).catch(errorHandler);
        }
    })

    var constraints = {
        video: true,
        audio: false,
    };

    if (navigator.mediaDevices.getUserMedia) {
        console.log('yeah your device is ok~')
        navigator.mediaDevices.getUserMedia(constraints).then(getUserMediaSuccess).catch(errorHandler);
    } else {
        console.log('Your browser does not support getUserMedia API');
    }
}

//将得到的视频流赋值给全局变量
function getUserMediaSuccess(stream) {
    localStream = stream;
    localVideo.srcObject = stream;
}

//前端界面start按钮绑定的事件，若点击start按钮，则执行start函数，传入参数为true，参数名为isCaller
function start(isCaller) {
    peerConnection = new RTCPeerConnection(peerConnectionConfig);
    //onicecandidate是一个回调函数，用于监听访问者的ice candidate，
    //客户端上传自己的ice candidate，以便stun服务器协助通信
    peerConnection.onicecandidate = gotIceCandidate;
    peerConnection.ontrack = gotRemoteStream;
    if(localStream) peerConnection.addStream(localStream);

    //若isCaller的值为true，则执行createOffer函数，向被叫发送视频连接请求
    if (isCaller) {
        peerConnection.createOffer().then(createdDescription).catch(errorHandler);
    }
}

function gotMessageFromServer(message) {
    //若peerConnection变量还未创建，说明不是主叫，则通过start函数创建一个peerConnection变量来响应可能到来的offer请求
    if (!peerConnection) start(false);

    var signal = JSON.parse(message.data);

    // Ignore messages from ourself
    if (signal.uuid == uuid) return;

    if (signal.sdp) {
        peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp)).then(function () {
            // Only create answers in response to offers
            if (signal.sdp.type == 'offer') {
                //如果收到的消息类型是offer请求，则创建一个响应来建立视频会话
                peerConnection.createAnswer().then(createdDescription).catch(errorHandler);
            }
        }).catch(errorHandler);
    } else if (signal.ice) {
        peerConnection.addIceCandidate(new RTCIceCandidate(signal.ice)).catch(errorHandler);
    }
}

function gotIceCandidate(event) {
    if (event.candidate != null) {
        socket.emit('message', JSON.stringify({ 'ice': event.candidate, 'uuid': uuid, 'rooms': room }));
    }
}

function createdDescription(description) {
    peerConnection.setLocalDescription(description).then(function () {
        socket.emit('message', JSON.stringify({ 'sdp': peerConnection.localDescription, 'uuid': uuid, 'rooms': room }));
    });
}

function gotRemoteStream(event) {
    console.log('got remote stream');
    remoteVideo.srcObject = event.streams[0];
    console.log(remoteVideo.srcObject)
}

function errorHandler(error) {
    alert(error.toString())
    console.log(error);
}

// Taken from http://stackoverflow.com/a/105074/515584
// Strictly speaking, it's not a real UUID, but it gets the job done here
function createUUID() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    }

    


    return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
}

```

> #### 后端

```Javascript
const HTTPS_PORT = 8443;
const fs = require('fs');

const serverConfig = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
};

// ----------------------------------------------------------------------------------------

var express = require('express');
const app = express();
const https = require('https');
// const httpsServer = https.createServer(serverConfig, handleRequest);
const httpsServer = https.createServer(serverConfig, app);
const { Server } = require('socket.io');
const io = new Server(httpsServer);
//io.listen(httpsServer).sockets;
const path = require('path')
app.use(express.static(path.join(__dirname, '../public')));
// ----------------------------------------------------------------------------------------

// Create a server for handling websocket calls
//const io = new WebSocketServer({ server: httpsServer });
const os=require('os')
function getIpAddress() {
  var interfaces = os.networkInterfaces() //获取网络接口
  for (var dev in interfaces) {
    let iface = interfaces[dev]
    for (let i = 0; i < iface.length; i++) {
      let { family, address, internal } = iface[i]
      if (dev.search('WLAN')!=-1&&family === 'IPv4' && address !== '127.0.0.1' && !internal) {
        return address
      }
    }
  }
}
const ip=getIpAddress()
io.on('connection', function (socket) {
  // const sockets = io.allSockets();
  // console.log(sockets);
  // const sockets = io.fetchSockets();
  // for (const socket of sockets)
  //   console.log(socket.id);

  socket.on('txt_message', function (message) {
    console.log('socket.txt_message triggered in server.js')

    io.to(message.rooms).emit('receiveMsg', message);
  });

  socket.on('error', (err) => {
    console.log(err);
  })

  socket.on('rooms', function (rooms) {
    var count = 0;
    var message = JSON.parse(rooms);
    socket.join(message.rooms);
    console.log(socket.id + '成功加入' + message.rooms);
    io.in(message.rooms).allSockets().then(items => {
      items.forEach(item => {
        count = count + 1;
      })
    });
    console.log(count);
  })

  socket.on("disconnect", async () => {
    const sockets = await io.fetchSockets();
    for (const socket of sockets)
      console.log(socket.id);
  });
  socket.on('message',(msg)=>{
    console.log('server received message event')
    var data=JSON.parse(msg)
    io.to(data.rooms).emit('message',msg)
    // console.log(JSON.parse(msg))
  })
});


httpsServer.listen(HTTPS_PORT, ip);
console.log(`Server running. Visit https://${ip}:` + HTTPS_PORT + ' in Firefox/Chrome'
);

```

> ## 成品效果

> ### pc端
![登录界面](/images/Project1/login.jpg)

![界面](/images/Project1/interface.jpg)

![被呼叫](/images/Project1/pc_called.PNG)

> ### 移动端

![登录界面1](/images/Project1/pixel_login.jpg)
![界面1](/images/Project1/pixel_user_interface.png)
![被呼叫1](/images/Project1/pixel_called.jpg)
![通话界面1](/images/Project1/pixel_chatroom.jpg)

