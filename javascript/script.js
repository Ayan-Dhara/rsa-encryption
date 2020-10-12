  class Chiper{
   "use strict";
   #key=null;
   #private=null;
   #public=null;
   #bits=8;
   #count=1;
   #minBits=8;
   #maxBits=16;
   #n=[];
   #e=[];
   #d=[];
   constructor(key_bits,bits_count){
    try{
     if(key_bits){
      if(Number.isInteger(key_bits)){
       if(key_bits%2)
        key_bits++;
       if(key_bits<this.#minBits)
        key_bits=this.#minBits;
       if(key_bits>this.#maxBits)
        key_bits=this.#maxBits;
       this.#bits=key_bits;
       if(bits_count)
        if(Number.isInteger(bits_count))
         if(bits_count>0)
          this.#count=bits_count;
      }
      else{
       if(bits_count)
        if(Number.isInteger(bits_count))
         this.#bits=bits_count;
       let keyLength=this.#bits*3/2;
       if(!(key_bits.length%keyLength)){
        for(let i=0;i<key_bits.length/keyLength;i++){
         let key=key_bits.substring(i*keyLength,(i+1)*keyLength);
         this.#n[i]=parseInt(key.substring(0,keyLength/3),16);
         this.#e[i]=parseInt(key.substring(keyLength/3,keyLength*2/3),16);
         this.#d[i]=parseInt(key.substring(keyLength*2/3,keyLength),16);
         this.#count=i+1;
        }
        this.#key=key_bits;
       }
      }
     }
    }catch(e){}
    if(!this.key){
     //create key
     let min=1;
     let max=1;
     for(let i=0;i<this.#bits;i++){
      max=max*2;
     }
     min=max/16;
     max--;
     let keyLen=this.#toHex(max).length;
     this.#key="";
     this.#private="";
     this.#public="";
     for(let i=0;i<this.#count;i++){
      let p=this.#randPrime(min,max);
      let q=this.#randPrime(min,max);
      let n=p*q;
      let phi=(p-1)*(q-1);
      let e=this.#pickE(phi);
      let d=this.#findD(e,phi);
      while((d<=0)||(e<=0)){
       e=this.#pickE(phi);
       d=this.#findD(e,phi);
      }
      let keyValid=1;
      for(let j=0;j<2*this.#bits;j++){
       let testInt=this.#randPrime(max,n);
       if(testInt!=this.#crypt(this.#crypt(testInt,e,n),d,n)){
        keyValid=0;
        break;
       }
      }
      if(!keyValid){
       i--;
       continue;
      }
      this.#n[i]=n;
      this.#e[i]=e;
      this.#d[i]=d;
      this.#key+=this.#toHex(n,keyLen*2);
      this.#private+=this.#toHex(n,keyLen*2);
      this.#public+=this.#toHex(n,keyLen*2);
      this.#key+=this.#toHex(d,keyLen*2);
      this.#private+=this.#toHex(d,keyLen*2);
      this.#key+=this.#toHex(e,keyLen*2);
      this.#public+=this.#toHex(e,keyLen*2);
     }
    }
   }
   
   toString(){
    return this.#key;
   }
   #toHex(n,l){
    if(!n)return "";
    if(!Number.isInteger(n))return "";
    let s=Number(n).toString(16);
    if(l){
     if(Number.isInteger(l)){
      while(s.length<l){
       s="0"+s;
      }
     }
    }
    return s;
   }
   #randInt(min,max){
    try{min=min*1;max=max*1;}catch(e){}
    if(!min)min=0;
    if((!max)&&(max!=0))max=0xffff;
    if(max<min){let tmp=min;min=max;max=tmp;}
    let d=max-min;
    if(min<0){min=-min;max=min+d;}
    return Math.floor(min+Math.random()*d);
   }
   #isPrime(n){
    if(n!=Math.floor(n))return false;
    if(n<=1)return false; 
    if(n<=3)return true;
    if(n%2==0||n%3==0)return false;
    for(let i=5;i*i<=n;i=i+6)
     if(n%i==0||n%(i+2)==0)
      return false;
    return true;
   }
   #randPrime(min,max){
    let n=this.#randInt(min,max);
    while(!this.#isPrime(n))
     n=this.#randInt(min,max);
    return n;
   }
   #extGCD(a,b){
    if(a==0)return [b,0,1];
    let GCD=this.#extGCD(b%a,a);
    return [GCD[0],GCD[2]-Math.floor(b/a)*GCD[1],GCD[1]];
   }
   #pickE(phi){
    let e=this.#randInt(2,phi-1);
    while(this.#extGCD(e,phi)[0]!=1){
     e=this.#randInt(2,phi-1);
    }
    return e;
   }
   #findD(e,phi){
    let d=this.#extGCD(e,phi)[1];
    if(d<0)d=d+phi;
    return d;
   }
   getPrivateKey(){
    return this.#private;
   }
   getPublicKey(){
    return this.#public;
   }
   getBitLength(){
    return this.#bits;
   }
   #crypt(b,e,m){
     if(m==1){
       print("Wrong:",b,e,m);
       return 0;
     }
     else{
       let r=1;
       b=b%m;
       while(e>0){
         if(e%2==1)
           r=(r*b)%m;
         e=Math.floor(e/2);
         b=(b*b)%m;
       }
       return r;
     }
   }
   encrypt(plainText,key,bits){
    if(!plainText)return "";
    plainText=encodeURIComponent(plainText);
    let textArray=plainText.split('').map(function(c){return c.charCodeAt(0);});
    for(let i=0;i<textArray.length;i++){
     textArray[i]=this.#crypt(textArray[i],this.#e[i%this.#count],this.#n[i%this.#count]);
    }
    let chiperText=textArray;
    return chiperText;
   }
   decrypt(chiperText,key,bits){
    if(!chiperText)return "";
    let textArray=chiperText;
    for(let i=0;i<textArray.length;i++){
     textArray[i]=this.#crypt(textArray[i],this.#d[i%this.#count],this.#n[i%this.#count]);
    }
    textArray=textArray.map(function(c){return String.fromCharCode(c);});
    let plainText=textArray.join('');
    //print("b:",plainText);
    try{
     plainText=decodeURIComponent(plainText);
    }catch(e){
     plainText="e: "+plainText;
    }
    return plainText;
   }
  }
