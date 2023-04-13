import BufferAead from '../../../lib/types/BufferAead';
import TestVector from '../types/TestVector';

export default interface TestDefinition {
  aead: BufferAead;
  testVector: TestVector;
}
