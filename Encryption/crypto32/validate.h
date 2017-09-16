#ifndef VALIDATE_H
#define VALIDATE_H

bool ValidateAll();
bool TestSettings();

bool ZKValidate();

bool CRC32Validate();
bool MD2Validate();
bool MD5Validate();
bool SHAValidate();
bool HAVALValidate();
bool TigerValidate();
bool RIPEMDValidate();

bool MD5MACValidate();
bool HMACValidate();
bool XMACCValidate();

bool CipherModesValidate();

bool DESValidate();
bool IDEAValidate();
bool SAFERValidate();
bool RC2Validate();
bool ARC4Validate();
bool RC5Validate();
bool BlowfishValidate();
bool Diamond2Validate();
bool ThreeWayValidate();
bool GOSTValidate();
bool SHARKValidate();
bool SHARK2Validate();
bool SEALValidate();
bool CASTValidate();
bool SquareValidate();
bool RC6Validate();
bool MARSValidate();
bool RijndaelValidate();
bool TwofishValidate();
bool SerpentValidate();

bool BBSValidate();
bool DHValidate();
bool MQVValidate();
bool RSAValidate();
bool ElGamalValidate();
bool NRValidate();
bool DSAValidate();
bool LUCValidate();
bool LUCDIFValidate();
bool LUCELGValidate();
bool RabinValidate();
bool RWValidate();
bool BlumGoldwasserValidate();
bool ECPValidate();
bool EC2NValidate();
bool ECDSAValidate();

#endif
