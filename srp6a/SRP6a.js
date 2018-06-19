var hash = require('hash.js');  // 引入Hash
var bigInterger = require("big-integer");  // 引入大整型
var commonFun = require('./srp6aCommonFun.js'); // 引入公共函数部分
var randomSize = 512/2/8;  // 随机数
var MinSaltSize = 16;  // salt的最小
var emptyString = "";   // 与err对比的
var arrEmpty = [];

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

function Srp6aBase() {
	this.generateSalt = function() {  // generate salt
	   var salt = new Array(MinSaltSize);
	   var err = this.randomBytes(salt);
	   if (err != emptyString) {
	   	  return emptyString;
	   }
	   salt = commonFun.bytes2Str(salt[salt.length-1]);  // 将其转为16进制字符串
	   return salt;
	}

	this.randomBytes = function(arr) { //random generate
		var err;
		if (arr.length <= 0) {
			err = "Parameter Error";
			return err; // return err
		}
		var rand = commonFun.randomWord(true, MinSaltSize, MinSaltSize);
		if (rand.length == 0) {
			err = "Generate Error";
			return err; 
		}
		arr.push(rand);
		return emptyString;
	}

	// Array copy to array 
	this._padCopy = function(dst, src) {
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

	this._setHash = function(b, hashName) {
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

	this._setParameter = function(b, g, N, bits) {
		if (b.err != emptyString) {
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
		var v_iN = commonFun.str2Bytes(b_iN);
		this._padCopy(b._N, v_iN);
	    
		b._g = new Array(b.byteLen);
		var b_ig = bigInterger(b.ig).toString(16);
		// PAD(g)
		this._padCopy(b._g, b_ig);

	    // Compute: k = SHA1(N | PAD(g)) 
		var h = b.hasher();
		var ghash = h.update(b._N).update(b._g).digest("hex");
		b.ik = bigInterger(ghash, 16);
	}

	this._computeU = function(hasher, bufLen, A, B) {
		if (A.length == 0 || B.length == 0) {
			return emptyString;
		}
		// Compute: u = SHA1(PAD(A) | PAD(B))
		var buf1 = new Array(bufLen);
		var buf2 = new Array(bufLen);
		var h = hasher();
		this._padCopy(buf1, A);
		this._padCopy(buf2, B);
		var u_temp = h.update(buf1).update(buf2).digest("hex").toString();
		
		var u = commonFun.str2Bytes(u_temp);
		for (var i = u.length - 1; i >= 0; i--) {
			if (u[i] != 0) {
				return u;
			}
		}
		return emptyString;
	}

	this._compute_u = function(b) {
		// Compute u = H(A, B)
		if (b._u.length == 0 && b.err == emptyString) {
			if (b._A.length == 0 || b._B.length == 0) {
				b.err = "A or B not set yet";
				return;
			}
			b._u = this._computeU(b.hasher, b.byteLen, b._A, b._B);
			if (b._u.length == 0) {
				b.err = "u can't be 0";
				return;
			}
		}
	}

	Srp6aBase.prototype.computeM1 = function(b) {
		if (b._M1.length == 0 && b.err == emptyString) {
			if (b._A.length == 0 || b._B.length == 0) {
				b.err = "A or B is not set yet";
				return emptyString;
			}
			if (b._S.length == 0) {
				b.err = "S must be computed before M1 and M2";
				return emptyString;
			}
			// Compute: M1 = SHA1(PAD(A) | PAD(B) | PAD(S))
			var buf1 = new Array(b.byteLen);
			var buf2 = new Array(b.byteLen);
			var buf3 = new Array(b.byteLen);
	        var h = b.hasher();
			this._padCopy(buf1, b._A);
			this._padCopy(buf2, b._B);
			this._padCopy(buf3, b._S);
			var u_temp = h.update(buf1).update(buf2).update(buf3).digest("hex").toString();
			
			var u = commonFun.str2Bytes(u_temp);
			for (var i = u.length - 1; i >= 0; i--) {
				if (u[i] != 0) {
					return u;
				}
			}
			return emptyString;
		}
	}

	Srp6aBase.prototype.computeM2 = function(b) {
		if (b._M2.length == 0 && b.err == emptyString) {
			var Mtemp = this.computeM1(b);
			if (b.err != emptyString  && Mtemp == undefined && Mtemp.length == 0) {
				return emptyString;
			}
			b._M1 = new Array(Mtemp.length);
			this._padCopy(b._M1, Mtemp);
			
			// Compute: M2 = SHA1(PAD(A) | M1 | PAD(S)) 
			var buf1 = new Array(b.byteLen);
			var buf2 = new Array(b.byteLen);
			var h = b.hasher();
			this._padCopy(buf1, b._A);
			this._padCopy(buf2, b._S);
			var u_temp = h.update(buf1).update(b._M1).update(buf2).digest('hex')

			b._M2 = commonFun.str2Bytes(u_temp);
			
		}
		return b._M2;
	}
}

function Srp6aServer() {
	Srp6aServer.prototype.iv = bigInterger(0);
	Srp6aServer.prototype.ib = bigInterger(0);
	Srp6aServer.prototype.iA = bigInterger(0);

	Srp6aServer.prototype.setV = function(v) {
	   if (commonFun.bigisZero(this.iv)&& this.err == emptyString && v != arrEmpty) {
	   		this.iv = bigInterger.fromArray(v, 256);
	   }
	}

	Srp6aServer.prototype.setA = function(A) {
		if (this.err == emptyString && A != arrEmpty) {
			if (A.length > this.byteLen) {
				this.err = "Invalid A, too large";
				return;
			} else {
				this.iA = bigInterger.fromArray(A, 256);
				// 若srv.iA % this.iN == 0
				if (commonFun.bigisZero(bigInterger(this.iA).mod(this.iN))) {
					this.err = "Invalid A, A%%N == 0";
					return;
				}
				this._A = new Array(this.byteLen);
				this._padCopy(this._A, A);
			}
		}
	}
 
	Srp6aServer.prototype._setB = function(b) {
		this.ib = bigInterger(b, 16);
	    // Compute: B = (k*v + g^b) % N
	    // Test console.log(bigInterger(bigInterger(111)).multiply(bigInterger(111)));
	    var i1 = bigInterger(this.ik).multiply(this.iv)

	    var i2 = bigInterger(this.ig).modPow(this.ib, this.iN);
	    // (i1 + i2) % N
	    var i3 = bigInterger(bigInterger(i1).add(i2)).mod(this.iN);

	    if (commonFun.bigisZero(i3)) {
	    	return arrEmpty;
	    }

	    this._B = new Array(this.byteLen);
	    var b_iN = bigInterger(i3).toString(16);
		var v_iN = commonFun.str2Bytes(b_iN);
	    this._padCopy(this._B, v_iN);
		return this._B;
	}
	Srp6aServer.prototype.generateB = function() {
		if (this._B.length == 0 && this.err == emptyString) {
			var buf = Array.apply(null, Array(randomSize)).map(function(item, i) {
				    return 0;
				});
			for (;this._B.length == 0;) {
				var err = this.randomBytes(buf);
				if (err != emptyString) {
					this.err = err;
					return emptyString;
				}
				var newbuf = commonFun.bytes2Str(buf[buf.length-1]);  // 将其转为16进制字符串
				_setB(newbuf);

				if (this._A.length > 0) {
					var u = _computeU(this.hasher, this.byteLen, this._A, this._B);
					if (u.length == 0) {
						this._B = arrEmpty;
					} else {
						this._u = u;
					}
				}
			}
		}
		return this._B;
	}
	Srp6aServer.prototype.serverComputeS = function() {
		if (this._S.length == 0 && this.err == emptyString) {
			if (this._A.length == 0 || commonFun.bigisZero(this.iv)) {
				this.err = "A or v is not set yet";
				return emptyString;
			}
			this.generateB();
			this._compute_u(this);
			if (this.err != emptyString) {
				return emptyString;
			}
			// Compute: S_host = (A * v^u) ^ b % N	
			var iu = bigInterger.fromArray(this._u, 256); // 根据数组生成对应的big类型
			// i1 = A * ((v^u)%N)
			var i1 = bigInterger(this.iv).modPow(iu, this.iN).multiply(this.iA).mod(this.iN);
			//(i1^b) % N
			i1 = bigInterger(i1).modPow(this.ib, this.iN);

			var b_i1 = bigInterger(i1).toString(16);
		    var v_i1 = commonFun.str2Bytes(b_i1);
		    this._S = new Array(this.byteLen);
			this._padCopy(this._S, v_i1);
		}
		return this._S;
	}
}
Srp6aServer.prototype = new Srp6aBase();
function NewServer(g, N, bits, hashName) {
	// srv = Object.assign(srp6aBase, Srp6aServer); 
	var srv = new Srp6aServer();
	srv = Object.assign(srv, commonFun.deepClone(srp6aBase)); 
	srv._setHash(srv, hashName);
	srv._setParameter(srv, g, N, bits);
	return srv;
}

// Client
function Srp6aClient() {
	
	Srp6aClient.prototype.identity = '';
	Srp6aClient.prototype.pass = '';
	Srp6aClient.prototype.salt = [];
	Srp6aClient.prototype.ix = bigInterger(0);
	Srp6aClient.prototype.ia = bigInterger(0);
	Srp6aClient.prototype.iB = bigInterger(0);
	Srp6aClient.prototype._v = [];

	Srp6aClient.prototype.setIdentity = function(id, pass) {
		this.identity = id;
		this.pass = pass;
	}

	Srp6aClient.prototype.setSalt = function(salt) {
		if (this.salt.length == 0 && (this.err == emptyString) && salt.length != 0) {
			this.salt = new Array(salt.length);
			this._padCopy(this.salt, salt);
			return true;
		}
		return false;
	}
    // compute x 
	Srp6aClient.prototype._computeX = function() {
		if (commonFun.bigisZero(this.ix) && this.err == emptyString) {
			if (this.identity.length == 0 || this.pass.length == 0 || this.salt.length == 0) {
				this.err = "id, pass or salt not set yet";
				return;
			}
			// Compute: x = SHA1(salt | SHA1(identity | ":" | pass)) 
			// h1.update(this.identity).update(':').update(this.pass).digest('hex') ==  h.1update(this.identity + ':' + this.pass).digest('hex')
	        var h = this.hasher();
	        var buf = h.update(this.identity + ':' + this.pass).digest();
			// reset hash
			var h2 = this.hasher();
			var newBuf = h2.update(this.salt).update(buf).digest('hex')

	        this.ix = bigInterger(newBuf, 16);
		}
	}
	Srp6aClient.prototype.computeV = function() {
		if (this._v.length == 0 && (this.err == emptyString)) {
			if (commonFun.bigisZero(this.iN)) {
				this.err = "Parameters (g,N) not set yet";
				return arrEmpty;
			}	
			this._computeX();
			if (this.err != emptyString) {
				return emptyString;
			}
			// Compute: v = g^x % N 
			this._v = new Array(this.byteLen);
			var i1 = bigInterger(this.ig).modPow(this.ix, this.iN);
			var b_iN = bigInterger(i1).toString(16);
			var v_iN = commonFun.str2Bytes(b_iN);
			this._padCopy(this._v, v_iN);
		}
		return this._v;
	}
	Srp6aClient.prototype._setA = function(a) {
		this.ia = bigInterger(a, 16);
	    // console.log(this.ia, this.iN)
	    // Compute: A = g^a % N 
		var i1 = bigInterger(this.ig).modPow(this.ia, this.iN);
		if (commonFun.bigisZero(i1)) {
			return arrEmpty;
		}
		var b_i1 = bigInterger(i1).toString(16);
		var v_i1 = commonFun.str2Bytes(b_i1);

		this._A = new Array(this.byteLen);
		this._padCopy(this._A, v_i1);
		return this._A;
	} 
	// set B
	Srp6aClient.prototype.setB = function(B) {
		if (this.err == emptyString && B != arrEmpty) {
			if (B.length > this.byteLen) {
				this.err = "Invalid B, too large";
				return;
			} else {
				this.iB = bigInterger.fromArray(B, 256);
				// 若srv.iB % this.iN == 0
				if (commonFun.bigisZero(bigInterger(this.iB).mod(this.iN))) {
					this.err = "Invalid B, B%%N == 0";
					return;
				}
				this._B = new Array(this.byteLen);
				this._padCopy(this._B, B);
			}
		}
	}
	Srp6aClient.prototype.generateA = function() {
		if (this._A.length == 0 && this.err == emptyString) {
			if (commonFun.bigisZero(this.iN)) {
				this.err = "Parameters (g,N) not set yet";
				return emptyString;
			}
			var err;
			var buf = Array.apply(null, Array(randomSize)).map(function(item, i) {
			    return 0;
			});
			while(this._A.length == 0) {
				err = this.randomBytes(buf);
				if (err != emptyString) {
					this.err = err;
					return emptyString;
				}
				var newbuf = commonFun.bytes2Str(buf[buf.length-1]);  // 将其转为16进制字符串
				_setA(newbuf);
			}
		}
		return this._A;
	}
	Srp6aClient.prototype.clientComputeS = function() {
		if (this._S.length == 0 && this.err == emptyString) {
			if (this._B.length == 0) {
				this.err = "B is not set yet";
				return emptyString;
			}
			this.generateA();
			this._computeX();
			this._compute_u(this);
			if (this.err != emptyString) {
				return emptyString;
			}
			// Compute: S_user = (B - (k * g^x)) ^ (a + (u * x)) % N 
			this._S = new Array(this.byteLen);
			var iu = bigInterger.fromArray(this._u, 256); // 根据数组生成对应的big类型
			// k * (g**x % N)
			var i1 = bigInterger(this.ig).modPow(this.ix, this.iN).multiply(this.ik);
			//B - (k * ((g**x) % N)) % N
		    i1 = bigInterger(i1).mod(this.iN);
			i1 = bigInterger(this.iB).subtract(i1);
			if (bigInterger(i1).compare(bigInterger(0)) < 0) {
				i1 = bigInterger(i1).add(this.iN);
			}
			// (a + (u * x)) % N
			var u1 = bigInterger(iu).multiply(this.ix).add(this.ia).mod(this.iN);
	        
			var u2 = bigInterger(i1).modPow(u1, this.iN);

			var b_i1 = bigInterger(u2).toString(16);
		    var v_i1 = commonFun.str2Bytes(b_i1);
			this._padCopy(this._S, v_i1);

		}
		return this._S;
	}

}
Srp6aClient.prototype = new Srp6aBase();
function NewClient(g, N, bits, hashName) {
		var cli = new Srp6aClient();
		cli = Object.assign(cli, commonFun.deepClone(srp6aBase));
		cli._setHash(cli, hashName);
		cli._setParameter(cli, g, N, bits);
		return cli;
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
	var id2 = "alice122";
	var pass2 = "password123";

	var salt =commonFun.str2Bytes(hexSalt);// // console.log(hash.utils.toArray(hexn));   

	var srv = NewServer(2, N, 1024,"SHA1");
	var cli = NewClient(2,N,1024,"SHA1");
	cli.setIdentity(id, pass); // 设置cli的id,pass
	cli.setSalt(salt);  // 设置cli的salt

	var v= cli.computeV();  // 计算cli的_v
	srv.setV(v);  // src设置iv
    
	var A = cli._setA(a)   // cli设置a
	srv.setA(A);   // srv设置A；
  
	var B = srv._setB(b);   // srv设置b
	cli.setB(B);   // cli设置B

	var S1 = srv.serverComputeS(); // 计算srv的S
	var S1Hex = commonFun.bytes2Str(S1);
	var S2 = cli.clientComputeS(); // 计算cli的S
	var S2Hex = commonFun.bytes2Str(S2);
	console.log("S1: ", S1.toString(16))
	console.log("S2: ", S2.toString(16))
	console.log("------------------")
	console.log("S1 hex: ", S1Hex)
	console.log("S2 hex: ", S1Hex)
	
	var M11 = srv.computeM1(srv);
	var M12 = cli.computeM1(cli);
	var M11Hex = commonFun.bytes2Str(M11);
	var M12Hex = commonFun.bytes2Str(M12);
	console.log("--------M1----------")
	console.log("M11: ", M11.toString())
	console.log("M12: ", M12.toString())
	console.log("------------------")
	console.log("M11 hex: ", M11Hex)
	console.log("M12 hex: ", M12Hex)

	var M21 = srv.computeM2(srv);
	var M22 = cli.computeM2(cli);
	var M21Hex = commonFun.bytes2Str(M21);
	var M22Hex = commonFun.bytes2Str(M22);
	console.log("--------M2----------")
	console.log("M21: ", M21.toString())
	console.log("M22: ",M22.toString())
	console.log("------------------")
	console.log("M21 hex: ", M21Hex)
	console.log("M22 hex: ", M22Hex)
}
TestSrp6aFixedParam();

// 下面只对浏览器有效
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
