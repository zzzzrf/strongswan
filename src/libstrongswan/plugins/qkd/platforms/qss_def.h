#ifndef __QSS_DEF_H__
#define __QSS_DEF_H__

#define SDK_VERSION "2.0.0"
#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_TYPE_DECRYPT 0
#define CRYPT_TYPE_ENCRYPT 1

#define ST_CONNECT_DEV_ERR 1
#define ST_CONNECT_DEV_NOR 2
#define ST_CONNECT_QSS_ERR 3
#define ST_CONNECT_QSS_NOR 4

#define USR_PIN_UNLOCK 0
#define USR_PIN_LOCK 1

#define QUERY_ID_BINDING 0
#define CLEAR_ID_BINDING 1
#define SET_ID_BINDING 2

#define KEY_BACKUP 0
#define KEY_RECOVERY 1

typedef void (*STCALLBACK)(int nSrvState, void* hDevHandle);

typedef int (*cbProgress)(int);

typedef struct __MiniDevInfo_st {
    char IssuerName[64];
    char DeviceName[128];
    char DeviceSerial[64];
    void* hDevHandle;
    unsigned int DeviceType;
    char SerialNumber[32];
} MiniDevInfo_st;

typedef struct st_BlockCipherParamInfo {
    unsigned char IV[32];
    unsigned int IVLen;
    unsigned int PaddingType;
    unsigned int FeedBitLen;
} BlockCipherParamInfo_st;

typedef struct st_DevUploadExtInfo {
    char devInfoExt[128];  //  IMEI、MAC地址、设备序列号等
    char devBrand[128];    // 设备品牌（XIAOMI、HUAWEI、APPLE）
    char devModel[128];    // 设备机型（红米note 9、iPhone 12)
    char appVer[64];       // app版本
    char sysType[32];      // 系统类型-android/ios/android-pad/ipad/pc/mac
    char sysVer[32];       // 10
} ExtDevInfo_st;

typedef struct st_DEVINFO {
    char Manufacturer[64];
    char Issuer[64];
    char Label[32];
    char SerialNumber[32];
    char HWVersion[8];
    char FirmwareVersion[8];
    unsigned int AlgSymCap;
    unsigned int AlgAsymCap;
    unsigned int AlgHashCap;
    unsigned int DevAuthAlgId;
    unsigned int TotalSpace;
    unsigned int FreeSpace;
    char DevId[64];
} DevInfo_st;

/*
#define	MAX_IV_LEN			32
typedef struct st_blockcipherparam
{
    unsigned char    IV[MAX_IV_LEN];
    unsigned int   IVLen;
    unsigned int   PaddingType;
    unsigned int   FeedBitLen;
}StBLOCKCIPHERPARAM;
*/

/*
文件属性
*/
typedef struct st_FILEATTRIBUTE {
    unsigned int FileSize;
    unsigned int ReadRights;
    unsigned int WriteRights;
} StFileAttribute;

typedef struct st_DevExportInfo {
    char DeviceSerial[64];
    unsigned char SysSignPubkey[65];
    unsigned char SysEncPubkey[65];
} DevRegistInfo_st;

/* algorithm */
#define SGD_SM1_ECB 0x00000101   /* SM1 ECB */
#define SGD_SM1_CBC 0x00000102   /* SM1 CBC */
#define SGD_SM1_CFB 0x00000104   /* SM1 CFB */
#define SGD_SM1_OFB 0x00000108   /* SM1 OFB */
#define SGD_SM1_MAC 0x00000110   /* SM1 MAC */
#define SGD_SSF33_ECB 0x00000201 /* SSF33 ECB */
#define SGD_SSF33_CBC 0x00000202 /* SSF33 CBC */
#define SGD_SSF33_CFB 0x00000204 /* SSF33 CFB */
#define SGD_SSF33_OFB 0x00000208 /* SSF33 OFB */
#define SGD_SSF33_MAC 0x00000210 /* SSF33 MAC */
#define SGD_SMS4_ECB 0x00000401  /* SMS4 ECB */
#define SGD_SMS4_CBC 0x00000402  /* SMS4 CBC */
#define SGD_SMS4_CFB 0x00000404  /* SMS4 CFB */
#define SGD_SMS4_OFB 0x00000408  /* SMS4 OFB */
#define SGD_SMS4_MAC 0x00000410  /* SMS4 MAC */

//错误码
#define SAR_OK 0                           //成功
#define SAR_UnknownErr 0x02000001          //异常错误
#define SAR_NotSupportYetErr 0x02000002    //不支持的服务
#define SAR_FileErr 0x02000003             //文件操作错误
#define SAR_ProviderTypeErr 0x02000004     //服务提供者参数类型错误
#define SAR_LoadProviderErr 0x02000005     //导人服务提供者接口错误
#define SAR_LoadDevMngApiErr 0x02000006    //导人设备管理接口错误
#define SAR_AlgoTypeErr 0x02000007         //算法类型错误
#define SAR_NameLenErr 0x02000008          //名称长度错误
#define SAR_KeyUsageErr 0x02000009         //密钥用途错误
#define SAR_ModulusLenErr 0x02000010       //模的长度错误
#define SAR_NotInitalizeErr 0x02000011     //未初始化
#define SAR_ObjErr 0x02000012              //对象错误
#define SAR_MemoryErr 0x02000100           //内存错误
#define SAR_TimeoutErr 0x02000101          //超时
#define SAR_IndataLenErr 0x02000200        //输人数据长度错误
#define SAR_IndataErr 0x02000201           //输人数据错误
#define SAR_GenRandErr 0x02000300          //生成随机数错误
#define SAR_HashObjErr 0x02000301          // HASH对象错
#define SAR_HashErr 0x02000302             // HASH运算错误
#define SAR_GenRsaKeyErr 0x02000303        //产生RSA密钥错
#define SAR_RsaModulusLenErr 0x02000304    // RSA密钥模长错误
#define SAR_CspImprtPubKeyErr 0x02000305   // CSP服务导人公钥错误
#define SAR_RsaEncErr 0x02000306           // RSA加密错误
#define SAR_RSADecEr 0x02000307            // RSA解密错误
#define SAR_HashNotEqualErr 0x02000308     // HASH值不相等
#define SAR_KeyNotFountErr 0x02000309      //密钥未发现
#define SAR_CertNotFountErr 0x02000310     //证书未发现
#define SAR_NotExportErr 0x02000311        //对象未导出
#define SAR_CertRevokedErr 0x02000316      //证书被吊销
#define SAR_CertNotYetValidErr 0x02000317  //证书未生效
#define SAR_CertHasExpiredErr 0x02000318   //证书已过期
#define SAR_CertVerifyErr 0x02000319       //证书验证错误
#define SAR_CertEncodeErr 0x02000320       //证书编码错误
#define SAR_DccryptPadErr 0x02000400       //解密时做补丁错误
#define SAR_MacLenErr 0x02000401           // MAC长度错误
#define SAR_KeyInfoTypeErr 0x02000402      //密钥类型错误
#define SAR_NotLogin 0x02000403            //没有进行登录认证
#define SAR_CREATE_SC_FAIL 0x02000404      //创建安全通道失败

#define SAR_BuffTooSmall 0x02000501              //缓存不足
#define SAR_ConnectDevErr 0x02000502             //打开设备错误
#define SAR_ConnectServiceErr 0x02000503         //连接密管失败
#define SAR_KeyNotEnough 0x02000504              //密钥不足
#define SAR_PendingApproval 0x02000505           //发行审核中
#define SAR_NeedChargeButReqKeySucc 0x02000506   //表示密钥协商成功，密钥需要充注/更新
#define SAR_NO_DEVICE 0x02000507                 //没有设备
#define SAR_Reject 0x02000508                    //发行设备审核不通过
#define SAR_KeyDestroyed 0x02000509              //密钥已被销毁
#define SAR_NoRoom 0x02000510                    //空间不足
#define SAR_UnlockPinPendingApproval 0x02000601  //请求成功，等待管理员审核
#define SAR_UnlockPinReject 0x02000602           //解锁PIN审核不通过
#define SAR_IS_CHARGING 0x2000603                //正在充注中
#define SAR_DEV_PAUSE 0x2000604                  //设备已暂停
#define SAR_NOT_HAS_QUWK 0x2000605               //没有quwk
#define SAR_OVER_REQ_LIMIT 0x2000606             //调用服务频率超过限制

#ifdef __cplusplus
}
#endif

#endif
