#ifndef __QSS_SDK_H__
#define __QSS_SDK_H__

#include "qss_def.h"

#ifdef __ANDROID__
#include <jni.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

//#define DLLEXT __attribute__((visibility("default")))

#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || \
    defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define DLLEXT __declspec(dllexport)
#else
#define DLLEXT __attribute__((visibility("default")))
#endif

///////////////////////////////
#ifdef __ANDROID__
DLLEXT int QSS_SetAndroidContext(jobject AppContext);
#endif
/////////////////////////////////////////
DLLEXT int QSS_Initialize(void **phAppHandle, const char *szConfigFile, const char *pAppSignature);

DLLEXT int QSS_DeviceNetIn(void *hAppHandle, void *hDevHandle, const char *pClientId, const char *pClientName,
                           ExtDevInfo_st *pUploadInfo);

DLLEXT int QSS_Finalize(void *hAppHandle);

DLLEXT int QSS_GetVersion(unsigned int *puiVersion);

DLLEXT int QSS_DetectDevice(MiniDevInfo_st *pDevInfoGroup, unsigned int *nDevNum, int iIfType);

DLLEXT int QSS_CheckDeviceStatus(void *hAppHandle, void *hDevHandle, MiniDevInfo_st *pDevInfo, unsigned int *pnStatus,
                                 int iIfType);

DLLEXT int QSS_VerifyPin(void *hAppHandle, void *hDevHandle, const char *szPin, unsigned int *pnRetryCount,
                         int iIfType);

DLLEXT int QSS_UserAuth(void *hAppHandle, void *hDevHandle);
DLLEXT int QSS_Login(void *hAppHandle, void *hDevHandle, const char *szPin, unsigned int *pnRetryCount);

DLLEXT int QSS_Logout(void *hAppHandle, void *hDevHandle);

DLLEXT int QSS_ChangePin(void *hAppHandle, void *hDevHandle, const char *szOldPin, const char *szNewPin,
                         unsigned int *pnRetryCount);

DLLEXT int QSS_UnlockPin(void *hAppHandle, void *hDevHandle, char *szAdmPin, char *szNewPin,
                         unsigned int *pnRetryCount);

DLLEXT int QSS_GetQKeyInfo(void *hAppHandle, void *hDevHandle, unsigned int *pnQKRemain, unsigned int *pnQKTotal, unsigned int * pnThreshold);

DLLEXT int QSS_RegSrvStatusMonitor(STCALLBACK pSrvCallBack, void *pParam);

DLLEXT int QSS_Pause(void *hAppHandle);

DLLEXT int QSS_Resume(void *hAppHandle);

DLLEXT int QSS_UpdateCfg(void *hAppHandle, char *szCfg);

DLLEXT int QSS_WriteLog(const char *pTag, const char *pMsg);

DLLEXT int QSS_ApplySessionQKey(void *hAppHandle, void *hDevHandle, unsigned char *szDstDevID, unsigned char *szKeyID,
                                unsigned int *pnKeyIDLen, void **phQKeyHandle, unsigned int nWorkType,
                                unsigned char *pAgreementData, int *pnAgreementDataLen, unsigned int nAlgID,
                                int nQKeyLen, unsigned int nValidityTime);

DLLEXT int QSS_GenerateQToken(void *hAppHandle, void *hDevHandle, unsigned char *pQToken, unsigned int *pnQTokenLen);

DLLEXT int QSS_ApplySessionQKeySpecifyQToken(void *hAppHandle, void *hDevHandle, unsigned char *szDstQToken,
                                             unsigned int nDstQTokenLen, unsigned char *szKeyID,
                                             unsigned int *pnKeyIDLen, void **phQKeyHandle,
                                             unsigned char *pAgreementData, int *pnAgreementDataLen,
                                             unsigned int nAlgID, int nQKeyLen, unsigned int nValidityTime);

DLLEXT int QSS_GetSessionQKeyByAgreementData(void *hAppHandle, void *hDevHandle, unsigned char *pAgreementData,
                                             int nAgreementDataLen, unsigned char *szKeyID, unsigned int *pnKeyIDLen,
                                             void **phQKeyHandle, unsigned int nAlgID);

DLLEXT int QSS_ApplyGroupSessionQKey(void *hAppHandle, void *hDevHandle, const char *pBussinessID,
                                     unsigned char *szKeyID, unsigned int *pnKeyIDLen, void **phQKeyHandle,
                                     unsigned int nAlgID, int nQKeyLen, unsigned int nValidityTime);

DLLEXT int QSS_GetSessionQKey(void *hAppHandle, void *hDevHandle, const char *pBussinessID, unsigned char *szKeyID,
                              unsigned int nAlgID, void **phQKeyHandle);
DLLEXT int QSS_GetSessionQKeyInfo(void *hAppHandle, void *hDevHandle, const char *pBussinessID, unsigned char *szKeyID,
                                  unsigned int nAlgID, void **phQKeyHandle, unsigned int *puCreateTime);

DLLEXT int QSS_ExportSessionQKey(void *hAppHandle, void *hDevHandle, unsigned char *szKeyID, unsigned char *pOutData,
                                 unsigned int *pnOutLen);

DLLEXT int QSS_ExportSessionQKeyWithEPK(void *hAppHandle, void *hDevHandle, unsigned char *szKeyID,
                                        unsigned char *pucPublicKey, unsigned int nPublicKeyLen,
                                        unsigned char *pOutData, unsigned int *pnOutLen);

DLLEXT int QSS_GetQrng(void *hAppHandle, void *hDevHandle, unsigned char *pQrngData, unsigned int *pnQrngLen);

DLLEXT int QSS_SoftAlgorithmInit(void *hAppHandle, void *hDevHandle, unsigned char *szKeyID, unsigned int nAlgID,
                                 void **phQKeyHandle);

DLLEXT int QSS_EncDecInit(void *hAppHandle, void *hDevHandle, void *hQKeyHandle, int bEncFlag,
                          BlockCipherParamInfo_st *pParamInfo);

DLLEXT int QSS_EncDecUpdate(void *hAppHandle, void *hDevHandle, void *hQKeyHandle, unsigned char *pInData,
                            unsigned int nInLen, unsigned char *pOutData, unsigned int *pnOutLen);
							
DLLEXT int QSS_EncDecBlockCrypt(void *hAppHandle, void *hDevHandle, void *hQKeyHandle, unsigned char *pInData,
                                unsigned int nInLen, unsigned char *pOutData, unsigned int *pnOutLen);


DLLEXT int QSS_EncDecFinal(void *hAppHandle, void *hDevHandle, void *hQKeyHandle, unsigned char *pOutData,
                           unsigned int *pnOutLen);

DLLEXT int QSS_MacInit(void *hAppHandle, void *hDevHandle, void *hQKeyHandle, BlockCipherParamInfo_st *pParamInfo,
                       void **phMac);
DLLEXT int QSS_BlockMac(void *hAppHandle, void *hDevHandle, void *hMacHandle, unsigned char *pInData,
                        unsigned int nInLen, unsigned char *pMacData, unsigned int *pnMacLen);
					   

DLLEXT int QSS_MacUpdate(void *hAppHandle, void *hDevHandle, void *hMacHandle, unsigned char *pInData,
                         unsigned int nInLen);

DLLEXT int QSS_MacFinal(void *hAppHandle, void *hDevHandle, void *hMacHandle, unsigned char *pMacData,
                        unsigned int *pnMacLen);

DLLEXT int QSS_CloseSessionQKeyHandle(void *hAppHandle, void *hDevHandle, void *hQKeyHandle);

DLLEXT int QSS_SecureAuth(void *hAppHandle, void *hDevHandle, unsigned int *pRandData);

DLLEXT int QSS_UsrDevRelease(void *hAppHandle, char *pClientId, void *hAdmDevHandle, void *hUsrDevHandle,
                             unsigned char usrDevAuthKey[16], char *szTypeName);

DLLEXT int QSS_DeviceKeyCharge(void *hAppHandle, void *hDevHandle, cbProgress cbFunc);

DLLEXT int QSS_QueryUsrPinStatus(void *hAppHandle, void *hDevHandle, int *iStatus);

DLLEXT int QSS_IdentityBindingOpt(void *hAppHandle, void *hDevHandle, int bindingOpt, char *szClientId);

DLLEXT int QSS_SetSymmKey(void *hAppHandle, void *hDevHandle, unsigned char *pbKey, unsigned int ulAlgID, void **phKey);

DLLEXT int QSS_KeyBackupAndRecovery(void *hAppHandle, void *hDevHandle, int iKeyOpt, char *password, char *szKeyPath);

DLLEXT int QSS_QueryQKeyInfo(void *hAppHandle, void *hDevHandle, unsigned int *iQKUpdateThres,
                             unsigned char reserve[128]);

//--------------QKR新增接口----------
DLLEXT int QSS_QKRRegister(void *hDevHandle, void *hHafsHandle, int iNetType, char *szUsrUri, char *szTicket,
                           char *szTmpCredential);

DLLEXT int QSS_QKRRegisterReadDataAndSendtoQss(void *hDevHandle, void *hHafsHandle, void *hHafsHandle2, int iNetType,
                                               char *szUsrUri, char *szTmpCredential);

DLLEXT int QSS_QKRRequestKey(void *hDevHandle, void *hHafsHandle, char *szUsrUri, char *szUsrCredential, char *szQksId,
                             char *szCreateDate, char *szUid, int iMode, int iNetType, int iType, int iKeyType,
                             int iKeyLength, char *szUnionId, char *szTopic, char *szFileName, char *szOpUsrUri,
                             char *szOpQksId);

DLLEXT int QSS_QKRGetKeyResponseAndSendtoQss(void *hDevHandle, void *hHafsHandle, char *szUsrUri, char *szUsrCredential,
                                             char *szUid, int iMode, int iNetType, int iType, int iKeyType,
                                             int iKeyLength, bool bExpandKey, char *szUnionId, char *szTopic,
                                             char *szFileName, char *szOpUsrUri, char *szOpQksId);

DLLEXT int QSS_QKRSymAndEnableKey(void *hDevHandle, char *szUid, int iKeyType, char *szUnionId, char *szTopic,
                                  char *szFileName, char *szKeyEndTime);

DLLEXT int QSS_QKROfflineShowRequests(void *hDevHandle, void *hHafsHandle, char *pReqFileNames, int *iReqFileNameLen);

DLLEXT int QSS_QKROfflineShowResponses(void *hDevHandle, void *hHafsHandle, char *pRespFileNames,
                                       int *iRespFileNameLen);

DLLEXT int QSS_Test(void *hAppHandle, void *hDevHandle, char *szAdmPin, char *szNewPin, unsigned int *pnRetryCount,
                    int type);

// DLLEXT int QSS_QKRDetectDevice(
//     MiniDevInfo_st * pDevInfoGroup,
//     unsigned int * nDevNum);

// DLLEXT int QSS_QKRVerifyPin(
//     void * hDevHandle,
//     char * szPin,
//     int * pnRetryCount);

//--------------QKR新增接口结束-------

/*

DLLEXT int QSS_DevCreateFile(
  void *hAppHandle,
  void *hDevHandle,
  const char *szFileName,
  unsigned int ulFileSize);


DLLEXT int QSS_DevDeleteFile(
  void *hAppHandle,
  void *hDevHandle,
  const char *szFileName);

DLLEXT int QSS_DevEnumFiles(
  void *hAppHandle,
  void *hDevHandle,
  char *szFileList,
  unsigned int *pulSize);

DLLEXT int QSS_DevGetFileInfo(
  void *hAppHandle,
  void *hDevHandle,
  const char *szFileName,
  StFileAttribute *pFileInfo);

DLLEXT int QSS_DevReadFile(
  void *hAppHandle,
  void *hDevHandle,
  const char *szFileName,
  unsigned int ulOffset,
  unsigned int ulSize,
  unsigned char *pbOutData,
  unsigned int *pulOutLen);

DLLEXT int QSS_DevWriteFile(
  void *hAppHandle,
  void *hDevHandle,
  const char *szFileName,
  unsigned int ulOffset,
  unsigned char *pbData,
  unsigned int ulSize);
*/
DLLEXT int QSS_SoftcardRestore(void *hAppHandle, void *hDevHandle, char *szDevName);

//运营平台对接新增接口
DLLEXT int QSS_ApplySMSCode(const char *pTelNum);
DLLEXT int QSS_ActivateLoginBySMSCode(const char *pTelNum, const char *pSmsCode, char *pUserId, char *pLoginToken);
DLLEXT int QSS_ActivateLoginByPassword(const char *pAccount, const char *pPassword, char *pUserId, char *pLoginToken);
DLLEXT int QSS_StartSoftCard(void * hAppHandle, const char *pUserId, const char *pLoginToken, const char * szPassword, void ** hDevHandle);
DLLEXT int QSS_CryptoSrvActivateReq(void * hAppHandle, void * hDevHandle, const char *pUserId, const char *pLoginToken);
DLLEXT int QSS_CryptoSrvManage(void * hAppHandle, void * hDevHandle, int bFlag);
DLLEXT int QSS_CommSrvActivateReq(void * hAppHandle, void * hDevHandle, const char *pUserId, char *pBusinessId, char *pBSPID, char *pBSPUrl);
DLLEXT int QSS_CommSrvManage(void * hAppHandle, void * hDevHandle, const char *pUserId, const char *pBusinessId, int bFlag);

#ifdef __cplusplus
}
#endif

#endif
