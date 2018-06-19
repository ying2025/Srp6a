var hash = require('hash.js');  // 引入Hash
var bigInterger = require("big-integer");  // 引入大整型
var commonFun = require('./srp6aInterface.js'); // 引入公共函数部分
var bigInt = bigInterger(0);
var randomSize = 512/2/8;  // 随机数
var MinSaltSize = 16;  // salt的最小
var nil = "";   // 与err对比的
var arrnil = [];
var srv = {};   // Server
var cli = {};  // client

var srp6aBase = {
	err: "",
	hashName: '',
	hasher: hash.sha,
	bits: 0,
	byteLen: 0,
	iN: bigInterger(0),  
	ig: bigInterger(0),
	ik: bigInterger(0),
	_N: [],
	_g: [],
	_A: [],
	_B: [],
	_S: [],
	_u: [],
	_M1: [],
	_M2: [],
	_K: []
};
function GenerateSalt() {  // generate salt
   var salt = new Array(MinSaltSize);
   var err = RandomBytes(salt);
   if (err != nil) {
   	  return nil;
   }
   salt = commonFun.Bytes2Str(salt[salt.length-1]);  // 将其转为16进制字符串
   return salt;
}
function RandomBytes(arr) { //random generate
	var err;
	if (arr.length <= 0) {
		err = "Parameter Error";
		return err; // 返回undefined
	}
	var rand = commonFun.randomWord(true, MinSaltSize, MinSaltSize);
	if (rand.length == 0) {
		err = "Generate Error";
		return err; 
	}
	arr.push(rand);
	return nil;
}

// Array copy to array 
function padCopy(dst, src) {
	if (src == undefined || dst.length < src.length) {
		console.error("Cann't reach here, dst length is shorter than src");
		return;
	}
	var n = dst.length - src.length;

	for (var i = 0; i < src.length; i++) {
		if (typeof src[i] == "string") {
			src[i] = parseInt(src[i]);
		}
		dst[i+n] = src[i];
	}
   
	for (n--; n >= 0; n--) {
		dst[n] = 0;
	}
}

function setHash(b, hashName) {
	if (hashName == 'SHA1') {
		b.hashName = 'SHA1';
		b.hasher   = hash.sha1;
	} else if(hashName == "SHA256") {
		b.hashName = "SHA256";
		b.hasher   = hash.sha256;
	} else {
		b.err = "Unsupported hash";
	}
}
function setParameter(b, g, N, bits) {
	if (b.err != nil) {
		return;
	}
	if (bits < 512 && bits < N.length * 8) {
		b.err = "bits must be 512 or above, and be len(N)*8 or above";
		return;
	}
	b.bits = bits;
	b.byteLen = parseInt((bits + 7) / 8);
	b.ig = bigInterger(g);  

	b._N = new Array(b.byteLen);
    b.iN = bigInterger(N, 16);
	var b_iN = bigInterger(b.iN).toString(16);
	var v_iN = commonFun.Str2Bytes(b_iN);
	padCopy(b._N, v_iN);
    
	b._g = new Array(b.byteLen);
	var b_ig = bigInterger(b.ig).toString(16);
	// PAD(g)
	padCopy(b._g, b_ig);

    // Compute: k = SHA1(N | PAD(g)) 
	var h = b.hasher();
	var ghash = h.update(b._N).update(b._g).digest("hex");
	b.ik = bigInterger(ghash, 16);
}

function computeU(hasher, bufLen, A, B) {
	if (A.length == 0 || B.length == 0) {
		return nil;
	}
	// Compute: u = SHA1(PAD(A) | PAD(B))
	var buf1 = new Array(bufLen);
	var buf2 = new Array(bufLen);
	var h = hasher();
	padCopy(buf1, A);
	padCopy(buf2, B);
	var u_temp = h.update(buf1).update(buf2).digest("hex").toString();
	
	var u = commonFun.Str2Bytes(u_temp);
	for (var i = u.length - 1; i >= 0; i--) {
		if (u[i] != 0) {
			return u;
		}
	}
	return nil;
}
// Compute U
function compute_u(b) {
	// Compute u = H(A, B)
	if (b._u.length == 0 && b.err == nil) {
		if (b._A.length == 0 || b._B.length == 0) {
			b.err = "A or B not set yet";
			return;
		}
		b._u = computeU(b.hasher, b.byteLen, b._A, b._B);
		if (b._u.length == 0) {
			b.err = "u can't be 0";
			return;
		}
	}
}
// Compute M1
function ComputeM1(b) {
	if (b._M1.length == 0 && b.err == nil) {
		if (b._A.length == 0 || b._B.length == 0) {
			b.err = "A or B is not set yet";
			return nil;
		}
		if (b._S.length == 0) {
			b.err = "S must be computed before M1 and M2";
			return nil;
		}
		// Compute: M1 = SHA1(PAD(A) | PAD(B) | PAD(S))
		var buf1 = new Array(b.byteLen);
		var buf2 = new Array(b.byteLen);
		var buf3 = new Array(b.byteLen);
        var h = b.hasher();
		padCopy(buf1, b._A);
		padCopy(buf2, b._B);
		padCopy(buf3, b._S);
		var u_temp = h.update(buf1).update(buf2).update(buf3).digest("hex").toString();
		
		var u = commonFun.Str2Bytes(u_temp);
		for (var i = u.length - 1; i >= 0; i--) {
			if (u[i] != 0) {
				return u;
			}
		}
		return nil;
	}
}
// Compute M2
function ComputeM2(b) {
	if (b._M2.length == 0 && b.err == nil) {
		var Mtemp = ComputeM1(b);
		if (b.err != nil  && Mtemp == undefined && Mtemp.length == 0) {
			return nil;
		}
		b._M1 = new Array(Mtemp.length);
		padCopy(b._M1, Mtemp);
		
		// Compute: M2 = SHA1(PAD(A) | M1 | PAD(S)) 
		var buf1 = new Array(b.byteLen);
		var buf2 = new Array(b.byteLen);
		var h = b.hasher();
		padCopy(buf1, b._A);
		padCopy(buf2, b._S);
		var u_temp = h.update(buf1).update(b._M1).update(buf2).digest('hex')

		b._M2 = commonFun.Str2Bytes(u_temp);
		
	}
	return b._M2;
}

var Srp6aServer = {
	// srp6aBase,
	iv: bigInterger(0),
	ib: bigInterger(0),
	iA: bigInterger(0)
};
function NewServer(g, N, bits, hashName) {
	srv = Object.assign(srp6aBase, Srp6aServer); 
	setHash(srv, hashName);
	setParameter(srv, g, N, bits);
	return srv;
}
// srv set V
function SetV(v) {
   if (commonFun.bigisZero(srv.iv)&& srv.err == nil && v != arrnil) {
   		srv.iv = bigInterger.fromArray(v, 256);
   }
}

function SetA(A) {
	if (srv.err == nil && A != arrnil) {
		if (A.length > srv.byteLen) {
			srv.err = "Invalid A, too large";
			return;
		} else {
			srv.iA = bigInterger.fromArray(A, 256);
			// 若srv.iA % srv.iN == 0
			if (commonFun.bigisZero(bigInterger(srv.iA).mod(srv.iN))) {
				srv.err = "Invalid A, A%%N == 0";
				return;
			}
			srv._A = new Array(cli.byteLen);
			padCopy(srv._A, A);
		}
	}
}

function set_b(b) {
	srv.ib = bigInterger(b, 16);
    // Compute: B = (k*v + g^b) % N
    // Test console.log(bigInterger(bigInterger(111)).multiply(bigInterger(111)));
    var i1 = bigInterger(srv.ik).multiply(srv.iv)

    var i2 = bigInterger(srv.ig).modPow(srv.ib, srv.iN);
    // (i1 + i2) % N
    var i3 = bigInterger(bigInterger(i1).add(i2)).mod(srv.iN);

    if (commonFun.bigisZero(i3)) {
    	return arrnil;
    }

    srv._B = new Array(srv.byteLen);
    var b_iN = bigInterger(i3).toString(16);
	var v_iN = commonFun.Str2Bytes(b_iN);
    padCopy(srv._B, v_iN);
	return srv._B;
}
function GenerateB() {
	if (srv._B.length == 0 && srv.err == nil) {
		var buf = Array.apply(null, Array(randomSize)).map(function(item, i) {
			    return 0;
			});
		for (;srv._B.length == 0;) {
			var err = RandomBytes(buf);
			if (err != nil) {
				srv.err = err;
				return nil;
			}
			var newbuf = commonFun.Bytes2Str(buf[buf.length-1]);  // 将其转为16进制字符串
			set_b(newbuf);

			if (srv._A.length > 0) {
				var u = computeU(srv.hasher, srv.byteLen, srv._A, srv._B);
				if (u.length == 0) {
					srv._B = arrnil;
				} else {
					srv._u = u;
				}
			}
		}
	}
	return srv._B;
}
// Server Compute S
function ServerComputeS() {
	if (srv._S.length == 0 && srv.err == nil) {
		if (srv._A.length == 0 || commonFun.bigisZero(srv.iv)) {
			srv.err = "A or v is not set yet";
			return nil;
		}
		GenerateB();
		compute_u(srv);
		if (srv.err != nil) {
			return nil;
		}
		// Compute: S_host = (A * v^u) ^ b % N	
		var iu = bigInterger.fromArray(srv._u, 256); // 根据数组生成对应的big类型
		// i1 = A * ((v^u)%N)
		var i1 = bigInterger(srv.iv).modPow(iu, srv.iN).multiply(srv.iA).mod(srv.iN);
		//(i1^b) % N
		i1 = bigInterger(i1).modPow(srv.ib, srv.iN);

		var b_i1 = bigInterger(i1).toString(16);
	    var v_i1 = commonFun.Str2Bytes(b_i1);
	    srv._S = new Array(srv.byteLen);
		padCopy(srv._S, v_i1);
	}
	return srv._S;
}

var Srp6aClient = {
    identity: '',
    pass: '',
    salt: [],
    ix: bigInterger(0),
    ia: bigInterger(0),
    iB: bigInterger(0),
    _v: []
}

function NewClient(g, N, bits, hashName) {
	cli = Object.assign(commonFun.deepClone(srp6aBase), Srp6aClient);
	setHash(cli, hashName);
	setParameter(cli, g, N, bits);
	return cli;
}
// set user id and password
function SetIdentity(id, pass) {
	cli.identity = id;
	cli.pass = pass;
}
// set random
function SetSalt(salt) {
	if (cli.salt.length == 0 && (cli.err == nil)) {
		cli.salt = new Array(salt.length);
		padCopy(cli.salt, salt);
		return true;
	}
	return false;
}
// generate private key
function compute_x() {
	if (commonFun.bigisZero(cli.ix) && cli.err == nil) {
		if (cli.identity.length == 0 || cli.pass.length == 0 || cli.salt.length == 0) {
			cli.err = "id, pass or salt not set yet";
			return;
		}
		// Compute: x = SHA1(salt | SHA1(identity | ":" | pass)) 
		// h1.update(cli.identity).update(':').update(cli.pass).digest('hex') ==  h.1update(cli.identity + ':' + cli.pass).digest('hex')
        var h = cli.hasher();
        var buf = h.update(cli.identity + ':' + cli.pass).digest();
		// reset hash
		var h2 = cli.hasher();
		var newBuf = h2.update(cli.salt).update(buf).digest('hex')

        cli.ix = bigInterger(newBuf, 16);
	}
}

function ComputeV() {
	if (cli._v.length == 0 && (cli.err == nil)) {
		if (cli.iN.isZero()) {
			cli.err = "Parameters (g,N) not set yet";
			return arrnil;
		}	
		compute_x();
		if (cli.err != nil) {
			return nil;
		}
		// Compute: v = g^x % N 
		cli._v = new Array(cli.byteLen);
		var i1 = bigInterger(cli.ig).modPow(cli.ix, cli.iN);
		var b_iN = bigInterger(i1).toString(16);
		var v_iN = commonFun.Str2Bytes(b_iN);
		padCopy(cli._v, v_iN);
	}
	return cli._v;
}

function set_a(a) {
	cli.ia = bigInterger(a, 16);
    // console.log(cli.ia, cli.iN)
    // Compute: A = g^a % N 
	var i1 = bigInterger(cli.ig).modPow(cli.ia, cli.iN);
	if (commonFun.bigisZero(i1)) {
		return arrnil;
	}
	var b_i1 = bigInterger(i1).toString(16);
	var v_i1 = commonFun.Str2Bytes(b_i1);

	cli._A = new Array(cli.byteLen);
	padCopy(cli._A, v_i1);
	return cli._A;
}
// Client set B
function SetB(B) {
	if (cli.err == nil && B != arrnil) {
		if (B.length > cli.byteLen) {
			cli.err = "Invalid B, too large";
			return;
		} else {
			cli.iB = bigInterger.fromArray(B, 256);
			// 若srv.iB % srv.iN == 0
			if (commonFun.bigisZero(bigInterger(cli.iB).mod(cli.iN))) {
				cli.err = "Invalid B, B%%N == 0";
				return;
			}
			cli._B = new Array(cli.byteLen);
			padCopy(cli._B, B);
		}
	}
}
// 生成A
function GenerateA() {
	if (cli._A.length == 0 && cli.err == nil) {
		if (commonFun.bigisZero(cli.iN)) {
			cli.err = "Parameters (g,N) not set yet";
			return nil;
		}
		var err;
		var buf = Array.apply(null, Array(randomSize)).map(function(item, i) {
		    return 0;
		});
		while(cli._A.length == 0) {
			err = RandomBytes(buf);
			if (err != nil) {
				cli.err = err;
				return nil;
			}
			var newbuf = commonFun.Bytes2Str(buf[buf.length-1]);  // 将其转为16进制字符串
			set_a(newbuf);
		}
	}
	return cli._A;
}
// 计算客户端的S
function ClientComputeS() {
	if (cli._S.length == 0 && cli.err == nil) {
		if (cli._B.length == 0) {
			cli.err = "B is not set yet";
			return nil;
		}
		GenerateA();
		compute_x();
		compute_u(cli);
		if (cli.err != nil) {
			return nil;
		}
		// Compute: S_user = (B - (k * g^x)) ^ (a + (u * x)) % N 
		cli._S = new Array(cli.byteLen);
		var iu = bigInterger.fromArray(cli._u, 256); // 根据数组生成对应的big类型
		// k * (g**x % N)
		var i1 = bigInterger(cli.ig).modPow(cli.ix, cli.iN).multiply(cli.ik);
		//B - (k * ((g**x) % N)) % N
	    i1 = bigInterger(i1).mod(cli.iN);
		i1 = bigInterger(cli.iB).subtract(i1);
		if (bigInterger(i1).compare(bigInterger(0)) < 0) {
			i1 = bigInterger(i1).add(cli.iN);
		}
		// (a + (u * x)) % N
		var u1 = bigInterger(iu).multiply(cli.ix).add(cli.ia).mod(cli.iN);
        
		var u2 = bigInterger(i1).modPow(u1, cli.iN);

		var b_i1 = bigInterger(u2).toString(16);
	    var v_i1 = commonFun.Str2Bytes(b_i1);
		padCopy(cli._S, v_i1);

	}
	return cli._S;
}

function TestSrp6aFixedParam() {
	var N = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
                "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
                "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
                "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
                "FD5138FE8376435B9FC61D2FC0EB06E3";
	var hexSalt = "BEB25379D1A8581EB5A727673A2441EE";   
	var a = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393";
	var b = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20";
	var id = "alice";
	var pass = "password123";

	var salt =commonFun.Str2Bytes(hexSalt);// // console.log(hash.utils.toArray(hexn));   

	var sServer = NewServer(2, N, 1024,"SHA1");
	var s = NewClient(2,N,1024,"SHA1");
	SetIdentity(id, pass); // 设置cli的id,pass
	SetSalt(salt);  // 设置cli的salt
	var v= ComputeV();  // 计算cli的_v
	SetV(v);  // src设置iv

	var A = set_a(a)   // cli设置a
	SetA(A);   // srv设置A；

	var B = set_b(b);   // srv设置b
	SetB(B);   // cli设置B

	var S1 = ServerComputeS(); // 计算srv的S
	var S1Hex = commonFun.Bytes2Str(S1);
	var S2 = ClientComputeS(); // 计算cli的S
	var S2Hex = commonFun.Bytes2Str(S2);
	console.log("S1: ", S1.toString(16))
	console.log("S2: ", S2.toString(16))
	console.log("------------------")
	console.log("S1 hex: ", S1Hex)
	console.log("S2 hex: ", S1Hex)
	// 
	var M11 = ComputeM1(srv);
	var M12 = ComputeM1(cli);
	var M11Hex = commonFun.Bytes2Str(M11);
	var M12Hex = commonFun.Bytes2Str(M12);
	console.log("--------M1----------")
	console.log("M11: ", M11.toString())
	console.log("M12: ", M12.toString())
	console.log("------------------")
	console.log("M11 hex: ", M11Hex)
	console.log("M12 hex: ", M12Hex)

	var M21 = ComputeM2(srv);
	var M22 = ComputeM2(cli);
	var M21Hex = commonFun.Bytes2Str(M21);
	var M22Hex = commonFun.Bytes2Str(M22);
	console.log("--------M2----------")
	console.log("M21: ", M21.toString())
	console.log("M22: ",M22.toString())
	console.log("------------------")
	console.log("M21 hex: ", M21Hex)
	console.log("M22 hex: ", M22Hex)
}
TestSrp6aFixedParam();


// window.utils = {
//   S1,
//   S1Hex,
//   S2,
//   S2Hex,
//   M11,
//   M12,
//   M11Hex,
//   M12Hex,
//   M21,
//   M22,
//   M21Hex,
//   M22Hex
// }
