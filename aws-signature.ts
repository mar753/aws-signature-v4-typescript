import * as CryptoJS from 'crypto-js';

import { AwsSignatureInputData } from './aws-signature-input.model';

/**
 * Amazon web services (AWS) Signature version 4 - EC2 API requests signing tool.
 * @class AwsSignature
 */
export class AwsSignature {
    constructor() {}

    /**
     * Generates the signature
     *
     * @param {AwsSignatureInputData} input - structure with data to be signed and keys
     * @param {Date} currentDate - optional parameter to pass custom date
     */
    generateSignature(input: AwsSignatureInputData, currentDate: Date = new Date()): Object {
        if (!input) {
            return {};
        }
        let amzDate = currentDate.toISOString().replace(/-|:|\..{3}/g, '');
        let dateStamp = amzDate.substr(0, 8);

        let canonicalHeaders =
          'content-type:' + input.contentType + '\n' + 'host:'
          + input.host + '\n' + 'x-amz-date:' + amzDate + '\n';

        let signedHeaders = 'content-type;host;x-amz-date';
        let payloadHash = CryptoJS.SHA256(input.requestParameters).toString();
        let canonicalRequest =
            input.method + '\n' + input.canonicalUri + '\n'
            + input.canonicalQuerystring + '\n' + canonicalHeaders + '\n'
            + signedHeaders + '\n' + payloadHash;

        let algorithm = 'AWS4-HMAC-SHA256';
        let credentialScope = dateStamp + '/' + input.region + '/' + input.service + '/' + 'aws4_request';
        let stringToSign =
            algorithm + '\n' +  amzDate + '\n' +  credentialScope +
            '\n' +  CryptoJS.SHA256(canonicalRequest).toString();

        let signingKey = this.getSignatureKey(
            input.secretKey, dateStamp, input.region, input.service);
        let signature = CryptoJS.HmacSHA256(stringToSign, signingKey).toString();

        let authorizationHeader =
            algorithm + ' ' + 'Credential=' + input.accessKey + '/'
            + credentialScope + ', ' +  'SignedHeaders=' + signedHeaders
            + ', ' + 'Signature=' + signature;

        return {'Content-Type': input.contentType,
                'X-Amz-Date': amzDate,
                'Authorization': authorizationHeader};
    }

    private getSignatureKey(
        key: string,
        dateStamp: string,
        regionName: string,
        serviceName: string): any
    {
        var kDate = CryptoJS.HmacSHA256(dateStamp, "AWS4" + key);
        var kRegion = CryptoJS.HmacSHA256(regionName, kDate);
        var kService = CryptoJS.HmacSHA256(serviceName, kRegion);
        var kSigning = CryptoJS.HmacSHA256("aws4_request", kService);
        return kSigning;
    }
}
