#include <stsafe_common.h>

/************************ Generate Unsigned Bytes Array ************************/

/*
 * Use the STSAFE A110 module to generate an array of random unsigned bytes.
 */
uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t *handle, uint8_t size, uint8_t *random)
{
  if (random == NULL)
  {
    return (1);
  }

  printf("  Request from STSAFE A110 to generate a %d bytes random number\r\n", size);

  StSafeA_LVBuffer_t TrueRandom;
  TrueRandom.Data = random;
  return ((uint8_t) StSafeA_GenerateRandom(handle, STSAFEA_EPHEMERAL_RND, size, &TrueRandom, STSAFEA_MAC_NONE));
}
