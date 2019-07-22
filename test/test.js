import test from 'ava';
import Easydes from '../easydes';

test('正常系テスト(string)', t => {
  const cipher = new Easydes('foo');
  t.is(cipher.decrypt('eHOxmiUiyV5ZzJwsWU/dOg=='), 'abc');
  t.is(cipher.decrypt('oIIbPyQtcnbc4delfaqMRQ=='), 'ほげ');
  t.is(cipher.decrypt('W0m/cMXRuAtOn3F52thHxCtQ616dAa0NChzayJ7noMff1w=='),
       '1234567890abcdef');
  t.is(cipher.decrypt(
    'VNG6DcvRz7nBSK2sWxDeWMpDWmgV3nqyziK3pGD+kX4n6xjXS4klvw==',
  ), 'abcdefghijklmnopqrstuvwxyz');
  t.is((new Easydes('foobarbaz')).decrypt('//+JJMw0ZUQdkJkwrJpI2A=='),
       'abcd');
});

test('正常系テスト(array)', t => {
  const cipher = new Easydes('foobarbaz');
  t.deepEqual(cipher.decrypt([
    'ae+vjmOwtAsh5EPUY6Spuw==',
    'cUiVkJR5U1cq2WPICzis9w==',
    'Ao54RI5DDZvAJzNQIPhm6Q==',
  ]), ['foo', 'bar', 'baz']);
});

test('正常系テスト(object)', t => {
  const cipher = new Easydes('foobarbaz');
  t.deepEqual(cipher.decrypt({
    foo: 'eFaNA7Miqj0fpydR/BO6gw==',
    bar: 'dr5LFIY0HH9OmHV/fpBzow==',
    baz: 'UGHbl3uqoMQqArVPO5AJkg==',
  }), {
    foo: 'foo',
    bar: 'bar',
    baz: 'baz'
  });
  t.deepEqual(cipher.decrypt({
    foo: ['eFaNA7Miqj0fpydR/BO6gw=='],
    bar: {baz: 'dr5LFIY0HH9OmHV/fpBzow=='},
  }), {
    foo: ['foo'],
    bar: {baz: 'bar'},
  });
});

test('復号できなかったら入力文字列を返す', t => {
  const cipher = new Easydes('bar');
  t.is(cipher.decrypt('foobar'), 'foobar');
  t.is(cipher.decrypt('Zm9vYmFyCg=='), 'Zm9vYmFyCg==');
  t.is(cipher.decrypt('MTIzNDU2Nzg5MGFiY2RlZgo='), 'MTIzNDU2Nzg5MGFiY2RlZgo=');
});

test('OpenSSLエラーで死なない', t => {
  const cipher = new Easydes('baz');
  t.is(cipher.decrypt('MTIzNDU2Nzg5MGFiY2RlCg=='), 'MTIzNDU2Nzg5MGFiY2RlCg==');
  t.is(cipher.decrypt('eHOxmiUiyV5ZzJwsWU/dOg=='), 'eHOxmiUiyV5ZzJwsWU/dOg==');
});
