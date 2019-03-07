#include "main_define.h"
#include "drv_fun.h"
#include "key.h"
#include "FsFile.h"
#include "FsCos.h"
#include "cos.h"
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
static const unsigned char root_key[D3DES_KEY_BYTES] = {0X85,0XF4,0X34,0X26,0XA2,0X94,0XFE,0X97,0X5D,0XFB,0XE5,0X51,0X7F,0XC2,0X6E,0X3B};

static const unsigned char read_sec_key_apdu[APDU_HEAD_BYTES] = {FSA_CLA,FSA_INS_READ_RECORD,SFI_FLAG | PH_KEY_EF_SFI,SEC_KEY_RECORD_INDEX,PH_KEY_EF_RECORD_LEN};
static const unsigned char read_ktos_key_apdu[APDU_HEAD_BYTES] = {FSA_CLA,FSA_INS_READ_RECORD,SFI_FLAG | PH_KEY_EF_SFI,TRANS_KTOS_KEY_RECORD_INDEX,PH_KEY_EF_RECORD_LEN};
static const unsigned char read_sotk_key_apdu[APDU_HEAD_BYTES] = {FSA_CLA,FSA_INS_READ_RECORD,SFI_FLAG | PH_KEY_EF_SFI,TRANS_STOK_KEY_RECORD_INDEX,PH_KEY_EF_RECORD_LEN};

static unsigned char trans_key_random_buf[TRANS_KEY_RANDOM_BYTES];
static unsigned char trans_key_timestamp_buf[TRANS_KEY_TIMESTAMP_BYTES];


////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int KeyVerify(unsigned char *pkey,int key_len,int type,unsigned char *pv)
{
	int ret;
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	unsigned char encode_buf[DES_BLOCK_BYTES];
	ret = 0;
	if((key_len != DES_KEY_BYTES) && (key_len != D3DES_KEY_BYTES) && (key_len != D3DES_DOUKEY_BYTES))
	{
		return -2;
	}
	
	if(key_len == DES_KEY_BYTES)
	{
		ret = DES_Init(pkey,DES_KEY_BYTES);
		ret += DES_Run_ECB(DES_ENCRYPT,(UINT8 *)(ivbuf),encode_buf,DES_BLOCK_BYTES);
		if(ret != RT_OK)
			return -1;
	}
	else
	{
		ret = DES_Init(pkey,key_len);
		ret += DES3_Run_ECB(DES_ENCRYPT,(UINT8 *)(ivbuf),encode_buf,DES_BLOCK_BYTES);
		if(ret != RT_OK)
			return -1;
	}

	if(type == CAL_MAC)
	{
		MyMemcpy((void *)(pv),(void *)(encode_buf),KEY_MAC_BYTES);
	}
	else if(type == CMP_MAC)
	{
		ret = MyMemcmp((void *)(pv),(void *)(encode_buf),KEY_MAC_BYTES);
		if(ret != 0)
			return -101;
	}
	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

void KeyTranskeyDataInit(unsigned char *ptimestamp,int bytes,unsigned char *prandom)
{
	Trng_Init(0);
	Trng_GenRandom((UINT8 *)(trans_key_random_buf),sizeof(trans_key_random_buf));
	MyMemcpy((void *)(prandom),(void *)(trans_key_random_buf),TRANS_KEY_RANDOM_BYTES);
	
	MyMemset((void *)(trans_key_timestamp_buf),0x20,sizeof(trans_key_timestamp_buf));
	MyMemcpy((void *)(trans_key_timestamp_buf),(void *)(ptimestamp),bytes);
}


void KeyResetDataInit(void)
{
	MyMemset((void *)(trans_key_random_buf),0x00,sizeof(trans_key_random_buf));
	MyMemset((void *)(trans_key_timestamp_buf),0x00,sizeof(trans_key_timestamp_buf));
}

int KeyGenTrankey(unsigned char *ptranskey)
{
	unsigned char prog_buf[D3DES_KEY_BYTES];
	unsigned char prog_key[D3DES_KEY_BYTES];
	int ret,i;
	
	MyMemcpy((void *)(prog_buf),(void *)(trans_key_random_buf),DES_KEY_BYTES);
	for(i = 0;i < DES_KEY_BYTES;i++)
		prog_buf[DES_KEY_BYTES + i] = ~trans_key_random_buf[i];
	
	ret = DES_Init((UINT8 *)root_key,D3DES_KEY_BYTES);
	ret += DES3_Run_ECB(DES_ENCRYPT,prog_buf,prog_key,D3DES_KEY_BYTES);
	if(ret != RT_OK)
		return ALG_ERR;
	
	
	ret = DES_Init((UINT8 *)prog_key,D3DES_KEY_BYTES);
	ret += DES3_Run_ECB(DES_ENCRYPT,trans_key_timestamp_buf,ptranskey,D3DES_KEY_BYTES);
	if(ret != RT_OK)
		return ALG_ERR;	

	KeyResetDataInit();
	return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

int KeyGenSecKey(void)
{
	int ret = 0;
	int index = 0;
	unsigned short sn_len;
	unsigned char chip_sn[128];
	unsigned char random[D3DES_KEY_BYTES];
	unsigned char temp_buf[D3DES_KEY_BYTES];
	unsigned char prog_buf[D3DES_KEY_BYTES];
	unsigned char apdu_buf[PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	Trng_Init(0);
	Trng_GenRandom((UINT8 *)(random),D3DES_KEY_BYTES);
	EFC_ReadChipSN(chip_sn,&sn_len);
	
	for(index = 0;index < 16;index++)
		chip_sn[index] ^= chip_sn[index + 16];
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)random,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,chip_sn,prog_buf,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)random,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,prog_buf,temp_buf,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)random,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,temp_buf,prog_buf,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	MyMemset((void *)(apdu_buf),0xFF,sizeof(apdu_buf));
	index = 0;
	apdu_buf[index++] = FSA_CLA;
	apdu_buf[index++] = FSA_INS_UPDATE_RECORD;
	apdu_buf[index++] = SFI_FLAG | PH_KEY_EF_SFI;
	apdu_buf[index++] = SEC_KEY_RECORD_INDEX;
	apdu_buf[index++] = PH_KEY_EF_RECORD_LEN;
	apdu_buf[index++] = 0x01;
	apdu_buf[index++] = SEC_KEY_TYPE;
	apdu_buf[index++] = CIPPHER_ATTR;
	apdu_buf[index++] = D3DES_KEY_BYTES;
	
	ret = KeyVerify(prog_buf,D3DES_KEY_BYTES,CAL_MAC,&apdu_buf[index]);
	if(ret != RT_OK)
		return SYS_ERR;	
	index += KEY_MAC_BYTES;
	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)root_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,prog_buf,&apdu_buf[index],D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;		

	ret = Fs_IntUpdateRecord(apdu_buf,PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES,temp_buf,&index);
	if(ret != 0)
		return FSA_ERR;
	return 0;
}

int KeyCheckSecKey(void)
{
	int ret;
	int rsp_len;
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	const unsigned char read_sec_key_apdu[APDU_HEAD_BYTES] = {FSA_CLA,FSA_INS_READ_RECORD,SFI_FLAG | PH_KEY_EF_SFI,SEC_KEY_RECORD_INDEX,PH_KEY_EF_RECORD_LEN};
	
	ret = Fs_IntReadRecord((unsigned char *)read_sec_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != SEC_KEY_TYPE)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)root_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],sec_key,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(sec_key,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;	
	return 0;
}

int KeyGetSecKey(unsigned char *pkey)
{
	int ret;
	int rsp_len;
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	
	ret = Fs_IntReadRecord((unsigned char *)read_sec_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != SEC_KEY_TYPE)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)root_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],pkey,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(pkey,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;	
	return 0;	
}


int KeyInstallKtosKey(unsigned char *pktos)
{
	int ret = 0;
	int index = 0;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char apdu_buf[PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	
	MyMemset((void *)(apdu_buf),0xFF,sizeof(apdu_buf));
	index = 0;
	apdu_buf[index++] = FSA_CLA;
	apdu_buf[index++] = FSA_INS_UPDATE_RECORD;
	apdu_buf[index++] = SFI_FLAG | PH_KEY_EF_SFI;
	apdu_buf[index++] = TRANS_KTOS_KEY_RECORD_INDEX;
	apdu_buf[index++] = PH_KEY_EF_RECORD_LEN;
	apdu_buf[index++] = 0x01;
	apdu_buf[index++] = TRANS_KEY;
	apdu_buf[index++] = CIPPHER_ATTR;
	apdu_buf[index++] = D3DES_KEY_BYTES;
	
	ret = KeyVerify(pktos,D3DES_KEY_BYTES,CAL_MAC,&apdu_buf[index]);
	if(ret != RT_OK)
		return SYS_ERR;	
	index += KEY_MAC_BYTES;
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,pktos,&apdu_buf[index],D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;		
	ret = Fs_IntUpdateRecord(apdu_buf,PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES,sec_key,&index);
	if(ret != 0)
		return FSA_ERR;
	return 0;	
}

int KeyCheckKtosKey(void)
{
	int ret;
	int rsp_len;
	unsigned char ktos_key[D3DES_KEY_BYTES];
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
	{
		return SECKEY_NOT_EXIST_ERR;
	}
	ret = Fs_IntReadRecord((unsigned char *)read_ktos_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != TRANS_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],ktos_key,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(ktos_key,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;		
	return 0;
}

int KeyGetKtosKey(unsigned char *pktos)
{
	int ret;
	int rsp_len;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = Fs_IntReadRecord((unsigned char *)read_ktos_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != TRANS_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],pktos,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(pktos,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;		
	return 0;	
}

int KeyInstallStokKey(unsigned char *pstok)
{
	int ret = 0;
	int index = 0;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char apdu_buf[PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	
	MyMemset((void *)(apdu_buf),0xFF,sizeof(apdu_buf));
	index = 0;
	apdu_buf[index++] = FSA_CLA;
	apdu_buf[index++] = FSA_INS_UPDATE_RECORD;
	apdu_buf[index++] = SFI_FLAG | PH_KEY_EF_SFI;
	apdu_buf[index++] = TRANS_STOK_KEY_RECORD_INDEX;
	apdu_buf[index++] = PH_KEY_EF_RECORD_LEN;
	apdu_buf[index++] = 0x01;
	apdu_buf[index++] = TRANS_KEY;
	apdu_buf[index++] = CIPPHER_ATTR;
	apdu_buf[index++] = D3DES_KEY_BYTES;
	
	ret = KeyVerify(pstok,D3DES_KEY_BYTES,CAL_MAC,&apdu_buf[index]);
	if(ret != RT_OK)
		return SYS_ERR;	
	index += KEY_MAC_BYTES;
	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,pstok,&apdu_buf[index],D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;		
	ret = Fs_IntUpdateRecord(apdu_buf,PH_KEY_EF_RECORD_LEN + APDU_HEAD_BYTES,sec_key,&index);
	if(ret != 0)
		return FSA_ERR;
	return 0;	
}
int KeyCheckStokKey(void)
{
	int ret;
	int rsp_len;
	unsigned char stok_key[D3DES_KEY_BYTES];
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = Fs_IntReadRecord((unsigned char *)read_sotk_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != TRANS_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],stok_key,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(stok_key,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;		
	return 0;	
}
int KeyGetStokKey(unsigned char *pstok)
{
	int ret;
	int rsp_len;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char record_buf[PH_KEY_EF_RECORD_LEN + SW_BYTES];
	unsigned char ivbuf[DES_BLOCK_BYTES] = {0};
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = Fs_IntReadRecord((unsigned char *)read_sotk_key_apdu,APDU_HEAD_BYTES,record_buf,&rsp_len);
	if(ret != 0)
		return FSA_ERR;
	if(record_buf[KEY_TYPE_INDEX] != TRANS_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_ATTR_INDEX] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	if(record_buf[KEY_LEN_INDEX] != D3DES_KEY_BYTES)
		return KEY_NOT_EXIST_ERR;	
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,&record_buf[KEY_DATA_INDEX],pstok,D3DES_KEY_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	
	ret = KeyVerify(pstok,D3DES_KEY_BYTES,CMP_MAC,&record_buf[KEY_MAC_INDEX]);
	if(ret != RT_OK)
		return KEY_VERIFY_ERR;		
	return 0;	
}
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

int KeyDesDo(int encode_type,int cal_type,unsigned char *pkey,int key_bytes,unsigned char *pin,int in_bytes,unsigned char *pout)
{
	int ret;
	int i,j,l;
	unsigned char *ppin;
	unsigned char *ppout;
	unsigned char prog_buf[DES_BLOCK_BYTES];
	unsigned char xor_buf[DES_BLOCK_BYTES];
	unsigned char cippher_buf[DES_BLOCK_BYTES];

	if((in_bytes % DES_BLOCK_BYTES) || (in_bytes == 0))
		return -1;
	if((key_bytes != DES_KEY_BYTES) && (key_bytes != D3DES_KEY_BYTES) && (key_bytes != D3DES_DOUKEY_BYTES))
		return -2;
	
	j = in_bytes / DES_BLOCK_BYTES;
	i = 0;
	ppin = pin;	
	ppout = pout;
	ret = DES_Init((UINT8 *)pkey,key_bytes);
	if(ret != RT_OK)
		return ALG_ERR;		
	if(cal_type == 0)//ECB
	{
		do
		{
			ret = DES3_Run_ECB(encode_type,ppin,cippher_buf,DES_BLOCK_BYTES);
			if(ret != RT_OK)
				return ALG_ERR;		
			ppin += DES_BLOCK_BYTES;
			MyMemcpy((void *)(ppout),(void *)(cippher_buf),DES_BLOCK_BYTES);
			ppout += DES_BLOCK_BYTES;			
			i++;
		}while(i < j);
	}
	else //CBC
	{
		if(encode_type == DES_ENCRYPT)
		{
			MyMemcpy((void *)(prog_buf),(void *)(ppin),DES_BLOCK_BYTES);
			do
			{			
				ret = DES3_Run_ECB(encode_type,prog_buf,cippher_buf,DES_BLOCK_BYTES);
				if(ret != RT_OK)
					return ALG_ERR;		
				ppin += DES_BLOCK_BYTES;
				i++;
				if(i < j)
				{
					
					for(l = 0;l < DES_BLOCK_BYTES;l++)
						prog_buf[l] = cippher_buf[l] ^ ppin[l];	
				}					
				MyMemcpy((void *)(ppout),(void *)(cippher_buf),DES_BLOCK_BYTES);
				ppout += DES_BLOCK_BYTES;				
			}while(i < j);	
		}
		else 
		{
			MyMemset((void *)(prog_buf),0,DES_BLOCK_BYTES);
			do
			{			
				ret = DES3_Run_ECB(encode_type,ppin,cippher_buf,DES_BLOCK_BYTES);
				if(ret != RT_OK)
					return ALG_ERR;		
				i++;
				
				for(l = 0;l < DES_BLOCK_BYTES;l++)
					xor_buf[l] = prog_buf[l] ^ cippher_buf[l];		
				MyMemcpy((void *)(prog_buf),(void *)(ppin),DES_BLOCK_BYTES);
				MyMemcpy((void *)(ppout),(void *)(xor_buf),DES_BLOCK_BYTES);
				ppout += DES_BLOCK_BYTES;
				ppin += DES_BLOCK_BYTES;				
			}while(i < j);			
		}
	}
	return 0;
}

int KeyRsaVerify(unsigned char *psec_key,unsigned char *pkey_data,int bytes,int type,unsigned char *pmac)
{
	int i,j,l;
	int ret;
	unsigned char *ppkey_data;
	unsigned char prog_buf[DES_BLOCK_BYTES];
	unsigned char cippher_buf[DES_BLOCK_BYTES];
	
	if(bytes == 0)
		return -1;
	i = bytes % DES_BLOCK_BYTES;
	if(i > 0)
	{
		j = DES_BLOCK_BYTES - i;
		for(l = 0;l < j;l++)
			pkey_data[bytes + l] = 0x00;
	}
	j = bytes / DES_BLOCK_BYTES;
	if(i > 0)
		j++;
	i = 0;
	ppkey_data = pkey_data;
	MyMemcpy((void *)(prog_buf),(void *)(ppkey_data),DES_BLOCK_BYTES);
	do
	{
		ret = DES_Init((UINT8 *)psec_key,D3DES_KEY_BYTES);
		ret += DES3_Run_ECB(DES_ENCRYPT,prog_buf,cippher_buf,DES_BLOCK_BYTES);
		if(ret != RT_OK)
			return ALG_ERR;		
		ppkey_data += DES_BLOCK_BYTES;
		i++;
		if(i < j)
		{
			
			for(l = 0;l < DES_BLOCK_BYTES;l++)
				prog_buf[l] = cippher_buf[l] ^ ppkey_data[l];
		}
	}while(i < j);
	if(type == CAL_MAC)
	{
		MyMemcpy((void *)(pmac),(void *)(cippher_buf),KEY_MAC_BYTES);
	}
	else if(type == CMP_MAC)
	{
		ret = MyMemcmp((void *)(pmac),(void *)(cippher_buf),KEY_MAC_BYTES);
		if(ret != 0)
			return -101;
	}	
	return 0;
}

int KeyInstallPhPubKey(unsigned char *pph_pub,int bytes)
{
	int ret = 0;
	int index = 0;
	int mod,add,tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[(PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO))];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	MyMemset((void *)(prog_buf),0,sizeof(prog_buf));
	MyMemcpy((void *)(&prog_buf[KEY_DATA_INDEX]),(void *)(pph_pub),bytes);
	mod = bytes % DES_BLOCK_BYTES;
	add = 0;
	if(mod != 0)
		add = DES_BLOCK_BYTES - mod;
	tlen = bytes + add;

	index = 0;
	prog_buf[index++] = APP_KEY;
	prog_buf[index++] = CIPPHER_ATTR;
	prog_buf[index++] = tlen & 0xFF;
	prog_buf[index++] = (tlen >> 8) & 0xFF;
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CAL_MAC,&prog_buf[index]);
	if(ret != 0)
		return SYS_ERR;
	index += KEY_MAC_BYTES;
	
	ret = KeyDesDo(DES_ENCRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
	if(ret != 0)
		return ALG_ERR;
	index += tlen;
	
	ret = FsFile_WriteEf(DEFAULT_DF_FID,PH_PUB_KEY_EF_FID,0,index,prog_buf);
	if(ret != 0)
		return FSA_ERR;
	ret = FsFile_UpdateBinaryFlag(DEFAULT_DF_FID,PH_PUB_KEY_EF_FID);
	if(ret != 0)
		return FSA_ERR;	
	return 0;	
}

int KeyCheckPhPubKey(void)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[(PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO))];	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PH_PUB_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);;
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	return 0;	
}

int KeyGetPhPubKey(unsigned char *pph_pub,int *bytes)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[(PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO))];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PH_PUB_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	MyMemcpy((void *)(pph_pub),(void *)(&prog_buf[KEY_DATA_INDEX]),tlen);
	*bytes = tlen;
	return 0;	
}

int KeyInstallPhPriKey(unsigned char *pph_pri,int bytes)
{
	int ret = 0;
	int index = 0;
	int mod,add,tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	MyMemset((void *)(prog_buf),0,sizeof(prog_buf));
	MyMemcpy((void *)(&prog_buf[KEY_DATA_INDEX]),(void *)(pph_pri),bytes);
	mod = bytes % DES_BLOCK_BYTES;
	add = 0;
	if(mod != 0)
		add = DES_BLOCK_BYTES - mod;
	tlen = bytes + add;
	
	index = 0;
	prog_buf[index++] = APP_KEY;
	prog_buf[index++] = CIPPHER_ATTR;
	prog_buf[index++] = tlen & 0xFF;
	prog_buf[index++] = (tlen >> 8) & 0xFF;
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CAL_MAC,&prog_buf[index]);
	if(ret != 0)
		return SYS_ERR;
	index += KEY_MAC_BYTES;
	
	ret = KeyDesDo(DES_ENCRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
	if(ret != 0)
		return ALG_ERR;
	index += tlen;
	
	ret = FsFile_WriteEf(DEFAULT_DF_FID,PH_PRI_KEY_EF_FID,0,index,prog_buf);
	if(ret != 0)
		return FSA_ERR;
	ret = FsFile_UpdateBinaryFlag(DEFAULT_DF_FID,PH_PRI_KEY_EF_FID);
	if(ret != 0)
		return FSA_ERR;			
	return 0;	
}

int KeyCheckPhPriKey(void)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PH_PRI_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);;
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	return 0;	
}

int KeyGetPhPriKey(unsigned char *pph_pri,int *bytes)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PH_PRI_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	MyMemcpy((void *)(pph_pri),(void *)(&prog_buf[KEY_DATA_INDEX]),tlen);
	*bytes = tlen;
	return 0;	
}


int KeyInstallPbPubKey(unsigned char *pph_pub,int bytes)
{
	int ret = 0;
	int index = 0;
	int mod,add,tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	MyMemset((void *)(prog_buf),0,sizeof(prog_buf));
	MyMemcpy((void *)(&prog_buf[KEY_DATA_INDEX]),(void *)(pph_pub),bytes);
	mod = bytes % DES_BLOCK_BYTES;
	add = 0;
	if(mod != 0)
		add = DES_BLOCK_BYTES - mod;
	tlen = bytes + add;
	
	index = 0;
	prog_buf[index++] = APP_KEY;
	prog_buf[index++] = CIPPHER_ATTR;
	prog_buf[index++] = tlen & 0xFF;
	prog_buf[index++] = (tlen >> 8) & 0xFF;
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CAL_MAC,&prog_buf[index]);
	if(ret != 0)
		return SYS_ERR;
	index += KEY_MAC_BYTES;
	
	ret = KeyDesDo(DES_ENCRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
	if(ret != 0)
		return ALG_ERR;
	index += tlen;
	
	ret = FsFile_WriteEf(DEFAULT_DF_FID,PB_PUB_KEY_EF_FID,0,index,prog_buf);
	if(ret != 0)
		return FSA_ERR;
	ret = FsFile_UpdateBinaryFlag(DEFAULT_DF_FID,PB_PUB_KEY_EF_FID);
	if(ret != 0)
		return FSA_ERR;		
	return 0;	
}

int KeyCheckPbPubKey(void)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO)];	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PB_PUB_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);;
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	return 0;	
}

int KeyGetPbPubKey(unsigned char *ppb_pub,int *bytes)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PUB_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PB_PUB_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;		
	MyMemcpy((void *)(ppb_pub),(void *)(&prog_buf[KEY_DATA_INDEX]),tlen);
	*bytes = tlen;
	return 0;	
}

int KeyInstallPbPriKey(unsigned char *ppb_pri,int bytes)
{
	int ret = 0;
	int index = 0;
	int mod,add,tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	MyMemset((void *)(prog_buf),0,sizeof(prog_buf));
	MyMemcpy((void *)(&prog_buf[KEY_DATA_INDEX]),(void *)(ppb_pri),bytes);
	mod = bytes % DES_BLOCK_BYTES;
	add = 0;
	if(mod != 0)
		add = DES_BLOCK_BYTES - mod;
	tlen = bytes + add;
	
	index = 0;
	prog_buf[index++] = APP_KEY;
	prog_buf[index++] = CIPPHER_ATTR;
	prog_buf[index++] = tlen & 0xFF;
	prog_buf[index++] = (tlen >> 8) & 0xFF;
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CAL_MAC,&prog_buf[index]);
	if(ret != 0)
		return SYS_ERR;
	index += KEY_MAC_BYTES;
	
	ret = KeyDesDo(DES_ENCRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
	if(ret != 0)
		return ALG_ERR;
	index += tlen;
	
	ret = FsFile_WriteEf(DEFAULT_DF_FID,PB_PRI_KEY_EF_FID,0,index,prog_buf);
	if(ret != 0)
		return FSA_ERR;
	ret = FsFile_UpdateBinaryFlag(DEFAULT_DF_FID,PB_PRI_KEY_EF_FID);
	if(ret != 0)
		return FSA_ERR;		
	return 0;	
}

int KeyCheckPbPriKey(void)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PB_PRI_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);;
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);
	
	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}
	
	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	return 0;	
}

int KeyGetPbPriKey(unsigned char *ppb_pri,int *bytes)
{
	int ret = 0;
	int tlen;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char prog_buf[PB_PRI_KEY_EF_SIZE - sizeof(EF_INFO)];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return SECKEY_NOT_EXIST_ERR;
	
	ret = FsFile_ReadEf(DEFAULT_DF_FID,PB_PRI_KEY_EF_FID,0,sizeof(prog_buf),prog_buf);
	if(ret != 0)
		return FSA_ERR;
	if(prog_buf[0] != APP_KEY)
		return KEY_NOT_EXIST_ERR;	
	if(prog_buf[1] != CIPPHER_ATTR)
		return KEY_NOT_EXIST_ERR;	
	tlen = prog_buf[2] | (prog_buf[3] << 8);

	if(prog_buf[1] == CIPPHER_ATTR)
	{
		ret = KeyDesDo(DES_DECRYPT,1,sec_key,D3DES_KEY_BYTES,&prog_buf[KEY_DATA_INDEX],tlen,&prog_buf[KEY_DATA_INDEX]);
		if(ret != 0)
			return ALG_ERR;
	}
	else
	{
		;
	}

	ret = KeyRsaVerify(sec_key,&prog_buf[KEY_DATA_INDEX],tlen,CMP_MAC,&prog_buf[KEY_MAC_INDEX]);
	if(ret != 0)
		return KEY_VERIFY_ERR;	
	MyMemcpy((void *)(ppb_pri),(void *)(&prog_buf[KEY_DATA_INDEX]),tlen);
	*bytes = tlen;
	return 0;	
}
int SavePhId(unsigned char *pid,int id_len)
{
	unsigned char apdu_buf[PH_ID_RECORD_LEN + APDU_HEAD_BYTES];
	int index = 0;
	int ret;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char ivbuf[DES_KEY_BYTES];
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return -101;
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	MyMemset((void *)(apdu_buf),0XFF,sizeof(apdu_buf));
	MyMemcpy((void *)(&apdu_buf[APDU_HEAD_BYTES]),(void *)(pid),id_len);
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_ENCRYPT,pid,&apdu_buf[APDU_HEAD_BYTES],KEY_ID_MAX_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;		
	
	apdu_buf[index++] = 0xFD;
	apdu_buf[index++] = 0xDC;	
	apdu_buf[index++] = PH_ID_EF_SFI | SFI_TAG;
	apdu_buf[index++] = PH_ID_RECORD_INDEX;
	apdu_buf[index++] = PH_ID_RECORD_LEN;	
	ret = Fs_IntUpdateRecord(apdu_buf,PB_ID_RECORD_LEN + APDU_HEAD_BYTES,apdu_buf,&index);
	if(ret != 0)
		return -102;
	return 0;
}
int GetPhId(unsigned char *pid,int *id_len)
{
	unsigned char record_buf[PH_SN_RECORD_LEN + APDU_HEAD_BYTES];
	int index = 0;
	int ret;
	unsigned char sec_key[D3DES_KEY_BYTES];
	unsigned char ivbuf[DES_KEY_BYTES];
	const unsigned char read_phid_apdu[APDU_HEAD_BYTES] = {0xFD,0xB2,PH_ID_EF_SFI | SFI_TAG,PH_ID_RECORD_INDEX,PH_ID_RECORD_LEN};
	
	*id_len = 0;
	
	ret = KeyGetSecKey(sec_key);
	if(ret != 0)
		return -101;
	
	MyMemset((void *)(record_buf),0,sizeof(record_buf));
	ret = Fs_IntReadRecord((unsigned char *)read_phid_apdu,APDU_HEAD_BYTES,record_buf,&index);
	if(ret != 0)
		return -102;
	
	MyMemset((void *)(ivbuf),0,sizeof(ivbuf));
	ret = DES_Init((UINT8 *)sec_key,D3DES_KEY_BYTES);
	ret += DES3_Run_CBC(DES_DECRYPT,record_buf,pid,KEY_ID_MAX_BYTES,ivbuf);
	if(ret != RT_OK)
		return ALG_ERR;	
	*id_len = KEY_ID_MAX_BYTES;
	return 0;
}

int KeyCheckKey(void)
{
	int key_state = 0;
	int ret ;
	ret = KeyCheckSecKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckKtosKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckStokKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckPhPubKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckPhPriKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckPbPubKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;
	ret = KeyCheckPbPriKey();
	if(ret != 0)
		key_state |= PH_SEC_KEY_ERR;	
	return key_state;
}






