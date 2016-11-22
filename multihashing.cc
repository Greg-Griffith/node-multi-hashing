#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;
using namespace Buffer;

Handle<Value> except(const char* msg) {
    Isolate* isolate = Isolate::GetCurrent();
    return isolate->ThrowException(v8::Exception::Error(String::NewFromUtf8(v8::Isolate::GetCurrent(),msg)));
}

void quark(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
    {
        args.GetReturnValue().Set(1);
		return;
    }

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
    {
        args.GetReturnValue().Set(2);
		return;
    }

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
		args.GetReturnValue().Set(3);
		return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void x11(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(4);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(5);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(6);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
	return;
}

void x5(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(7);
		return;
	}	

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(8);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(9);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void scrypt(const FunctionCallbackInfo<Value>& args) {

   if (args.Length() < 3)
	{
        args.GetReturnValue().Set(except("You must provide buffer to hash, N value, and R value"));
		return;
	}

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
	{
       args.GetReturnValue().Set(except("Argument should be a buffer object."));
		return;
	}

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(12);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void neoscrypt_hash(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 2)
	{
        args.GetReturnValue().Set(13);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(14);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

//    uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(15);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void scryptn(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 2)
	{
        args.GetReturnValue().Set(16);
		return;
	}

   Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(17);
		return;
	}

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(18);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void scryptjane(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 5)
	{
        args.GetReturnValue().Set(19);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(20);
		return;
	}

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(21);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void yescrypt(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(22);
		return;
	}

   Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(23);
		return;
	}

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(24);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void keccak(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(25);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(26);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(27);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void bcrypt(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(28);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(29);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(30);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void skein(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(31);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(32);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(33);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void groestl(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(34);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(35);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(36);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void groestlmyriad(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(37);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(38);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(39);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void blake(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(40);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(41);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(42);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void dcrypt(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(43);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(44);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(45);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void fugue(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(46);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(47);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(48);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void qubit(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(49);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(50);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(51);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void s3(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)	
	{
        args.GetReturnValue().Set(52);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(53);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(54);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void hefty1(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
        args.GetReturnValue().Set(55);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(56);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(57);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}


void shavite3(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(58);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(59);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(60);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void cryptonight(const FunctionCallbackInfo<Value>& args) {

    bool fast = false;

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(61);
	}

    if (args.Length() >= 2) 
	{
        if(!args[1]->IsBoolean())
		{
			args.GetReturnValue().Set(62);
			return;
		}
        fast = args[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(63);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(64);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void x13(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(65);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(66);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(67);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void x14(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(68);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(69);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(70);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void boolberry(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 2)
	{
        args.GetReturnValue().Set(71);
		return;
	}

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
	{
        args.GetReturnValue().Set(72);
		return;
	}

    if(!Buffer::HasInstance(target_spad))
	{
        args.GetReturnValue().Set(73);
		return;
	}

    if(args.Length() >= 3)
	{
        if(args[2]->IsUint32())
		{
            height = args[2]->ToUint32()->Uint32Value();
		}
        else
		{
			args.GetReturnValue().Set(74);
			return;
		}
	}

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(75);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void nist5(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(76);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(77);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(78);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void sha1(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(79);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(80);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(81);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void x15(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(82);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(83);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(84);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void fresh(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(85);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(86);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(87);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void jh(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(88);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(89);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    jh_hash(input, output, input_len);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(90);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void c11(const FunctionCallbackInfo<Value>& args) {

    if (args.Length() < 1)
	{
		args.GetReturnValue().Set(91);
		return;
	}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
	{
		args.GetReturnValue().Set(92);
		return;
	}

    char * input = Buffer::Data(target);
    char output[32];

//    uint32_t input_len = Buffer::Length(target);

    c11_hash(input, output);

    MaybeLocal<Object> buff = Buffer::New(v8::Isolate::GetCurrent(), output, 32);

    if(buff.IsEmpty())
    {
        args.GetReturnValue().Set(93);
        return;
    }

    Local<Value> lbuff = buff.ToLocalChecked();
    args.GetReturnValue().Set(lbuff);
    return;
}

void init(Handle<Object> exports) {
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"quark"), FunctionTemplate::New(v8::Isolate::GetCurrent(), quark)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"x11"), FunctionTemplate::New(v8::Isolate::GetCurrent(), x11)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"scrypt"), FunctionTemplate::New(v8::Isolate::GetCurrent(), scrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"scryptn"), FunctionTemplate::New(v8::Isolate::GetCurrent(), scryptn)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"scryptjane"), FunctionTemplate::New(v8::Isolate::GetCurrent(), scryptjane)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"yescrypt"), FunctionTemplate::New(v8::Isolate::GetCurrent(), yescrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"keccak"), FunctionTemplate::New(v8::Isolate::GetCurrent(), keccak)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"bcrypt"), FunctionTemplate::New(v8::Isolate::GetCurrent(), bcrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"skein"), FunctionTemplate::New(v8::Isolate::GetCurrent(), skein)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"groestl"), FunctionTemplate::New(v8::Isolate::GetCurrent(), groestl)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"groestlmyriad"), FunctionTemplate::New(v8::Isolate::GetCurrent(), groestlmyriad)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"blake"), FunctionTemplate::New(v8::Isolate::GetCurrent(), blake)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"fugue"), FunctionTemplate::New(v8::Isolate::GetCurrent(), fugue)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"qubit"), FunctionTemplate::New(v8::Isolate::GetCurrent(), qubit)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"hefty1"), FunctionTemplate::New(v8::Isolate::GetCurrent(), hefty1)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"shavite3"), FunctionTemplate::New(v8::Isolate::GetCurrent(), shavite3)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"cryptonight"), FunctionTemplate::New(v8::Isolate::GetCurrent(), cryptonight)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"x13"), FunctionTemplate::New(v8::Isolate::GetCurrent(), x13)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"x14"), FunctionTemplate::New(v8::Isolate::GetCurrent(), x14)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"boolberry"), FunctionTemplate::New(v8::Isolate::GetCurrent(), boolberry)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"nist5"), FunctionTemplate::New(v8::Isolate::GetCurrent(), nist5)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"sha1"), FunctionTemplate::New(v8::Isolate::GetCurrent(), sha1)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"x15"), FunctionTemplate::New(v8::Isolate::GetCurrent(), x15)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"fresh"), FunctionTemplate::New(v8::Isolate::GetCurrent(), fresh)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"s3"), FunctionTemplate::New(v8::Isolate::GetCurrent(), s3)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"neoscrypt"), FunctionTemplate::New(v8::Isolate::GetCurrent(), neoscrypt_hash)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"dcrypt"), FunctionTemplate::New(v8::Isolate::GetCurrent(), dcrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"jh"), FunctionTemplate::New(v8::Isolate::GetCurrent(), jh)->GetFunction());
    exports->Set(String::NewFromUtf8(v8::Isolate::GetCurrent(),"c11"), FunctionTemplate::New(v8::Isolate::GetCurrent(), c11 )->GetFunction());
}

NODE_MODULE(multihashing, init)
