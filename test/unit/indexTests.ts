import { assert } from 'assertthat';
// eslint-disable-next-line unicorn/import-index
import { dummy } from '../../lib/index';

suite('dummy test', (): void => {
  test('test.', async (): Promise<void> => {
    assert.that(dummy).is.equalTo(42);
  });
});
