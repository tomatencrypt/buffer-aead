// Flips last bit (least significant bit) of the buffer
const tamperBuffer = (source: Buffer): Buffer => {
  const tampered = Buffer.alloc(source.length);
  source.copy(tampered);

  // eslint-disable-next-line no-bitwise
  tampered[source.length - 1] ^= 1;

  return tampered;
};

export { tamperBuffer };
