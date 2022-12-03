import { AccessLog } from '../logs/accessLog';
import { Buffer } from '../globals';
import { v4 } from 'uuid';

export class TestKeys {
  static pubCa =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBITCByAIJAJIgM6o1Soz/MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
    'b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowGTEXMBUG\n' +
    'A1UEAwwORGV2ZWxvcG1lbnQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASz\n' +
    'mmKWEqdfYOcspvWpjyZlzDRj4ueX+VBMIh6PnyTDiF21CD9V/hCeJGMUBwOhA/0K\n' +
    'GBXjuHoEQWolytkNC4IdMAoGCCqGSM49BAMCA0gAMEUCIQCqtjjokBqyMe3h850n\n' +
    'HlXsfCDTLQe+Tq0YGX1s3Ac5zAIgW02bMx6mroNrFONplm6Li0HLIgCfXVOIS3BF\n' +
    'RQUGwhY=\n' +
    '-----END CERTIFICATE-----';

  static pubA =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBJzCBzwIJAPi05h3+oZR3MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
    'b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG\n' +
    'A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n' +
    'AQcDQgAEBshF/Y40TAHRdcLc8CU9iu+ZJz8W69Qrmbttu/i9WAMR8sX+sF/glcOS\n' +
    '5BmltKxfL49B5jBZmVenmyajT6tfITAKBggqhkjOPQQDAgNHADBEAiAXvw+CwR97\n' +
    'ahXX2PPRJq/gQ2gXS/x0pvKNo6521UutlgIgdOknrMA6v+SglkBu8USsKGRgqFa2\n' +
    'RCNGeW9w1K4rnPY=\n' +
    '-----END CERTIFICATE-----';

  static privA =
    '-----BEGIN PRIVATE KEY-----\n' +
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNxkH9Z8yVF7KHrLw\n' +
    'KP6IxRk1DYjHS6pYC8tXacYkizyhRANCAAQGyEX9jjRMAdF1wtzwJT2K75knPxbr\n' +
    '1CuZu227+L1YAxHyxf6wX+CVw5LkGaW0rF8vj0HmMFmZV6ebJqNPq18h\n' +
    '-----END PRIVATE KEY-----';

  static pubB =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBKTCBzwIJAPi05h3+oZR4MAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDkRldmVs\n' +
    'b3BtZW50IENBMB4XDTIyMTIwMzEyNTIwNFoXDTIzMTIwMzEyNTIwNFowIDEeMBwG\n' +
    'A1UEAwwVIm1vaXRvcjJAbW9uaXRvci5jb20iMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n' +
    'AQcDQgAE2tg3CN9AENSlkL6FONlWDX3wVKIKAZoziWHkZ/U/y0VvcSSke1DMY8Id\n' +
    'jXqmwJtK7OTjv3muQezMaAYdJc73/DAKBggqhkjOPQQDAgNJADBGAiEApED995lG\n' +
    'XEpbpG0nqrnwtXFiZAR9jC6SV9AJP85MF0ECIQC/d3C2oq/q8OLAbcNMagwyEw26\n' +
    '1MnS5F6OMRw1m0IXwA==\n' +
    '-----END CERTIFICATE-----';

  static privB =
    '-----BEGIN PRIVATE KEY-----\n' +
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqySZT+PKukQfGQGb\n' +
    'b3F8fZnpY8LYfadaZDaDwteHw1WhRANCAATa2DcI30AQ1KWQvoU42VYNffBUogoB\n' +
    'mjOJYeRn9T/LRW9xJKR7UMxjwh2NeqbAm0rs5OO/ea5B7MxoBh0lzvf8\n' +
    '-----END PRIVATE KEY-----\n';
}

export const exampleAccessLog = new AccessLog(
  'monitor',
  'owner',
  'tool',
  'jus',
  30,
  'aggregation',
  ['email', 'address']
);

export const base64decode = function (data: string | undefined) {
  return Buffer.from(data, 'base64').toString();
};

export const base64encode = function (data: string) {
  return Buffer.from(data).toString('base64');
};

export const modifyFirstChar = function (data: string | undefined) {
  if (data == null) {
    return '';
  }
  let modified = data;
  while (modified === data) {
    modified = v4().slice(0, 1) + data.slice(1, data.length);
  }
  return modified;
};

export const base64ToObj = function (data: string | undefined) {
  return JSON.parse(base64decode(data));
};

export const objToBase64 = function (data: object) {
  return base64encode(JSON.stringify(data));
};
