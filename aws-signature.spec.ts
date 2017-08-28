import { AwsSignature } from './aws-signature';
import { AwsSignatureInputData } from './aws-signature-input.model';

/**
 * Jasmine unit tests
 */

describe('aws-signature tests', () => {
    let signingTool: AwsSignature;

    function prepareAwsSignatureInput(): AwsSignatureInputData {
        let awsSignatureInputData = new AwsSignatureInputData();
        awsSignatureInputData.method = 'POST';
        awsSignatureInputData.canonicalUri = '/api/patient/1';
        awsSignatureInputData.host = 'test-api.com';
        awsSignatureInputData.region = 'eu-west-1';
        awsSignatureInputData.service = 'execute-api';
        awsSignatureInputData.accessKey = 'RDFKKSLFLWKWLFLSK';
        awsSignatureInputData.secretKey = 'dj8wHxsd213HdeoaBIDgdwoi*dd90';
        awsSignatureInputData.contentType = 'application/json';
        awsSignatureInputData.requestParameters = '{"name":"Mark","age":"43"}';
        awsSignatureInputData.canonicalQuerystring = '';
        return awsSignatureInputData;
    }

    beforeEach(() => { signingTool = new AwsSignature(); });

    it('should return correct signature', () => {
    let data = prepareAwsSignatureInput();
    let date = new Date('2017-08-20T10:00:22Z');
    let output = signingTool.generateSignature(data, date);
    expect(output['Content-Type']).toBe('application/json');
    expect(output['X-Amz-Date']).toBe('20170820T100022Z');
    expect(output['Authorization']).toBe(
        'AWS4-HMAC-SHA256 Credential=RDFKKSLFLWKWLFLSK/20170820/eu-west-1/' +
        'execute-api/aws4_request, SignedHeaders=content-type;host;x-amz-date,' +
        ' Signature=cff19fa73afeb64af9aa7365a3f1564cc936b195d2b612342f2c50fe32719a80');
    });

    it('should return empty object when input data is null or undefined', () => {
        let data = null;
        let date = new Date('2017-08-20T10:00:22Z');
        let output = signingTool.generateSignature(data, date);
        expect(Object.keys(output).length).toBe(0);
    });

});
