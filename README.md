# AWS Signature Version 4 handler in TypeScript

Tools written in TypeScript to handle AWS Signature Version 4 signing process of the EC2 API requests. Code uses CryptoJS library to generate the signature, thus this is a required dependency. Should be easy to integrate with an Angular 2/4 project (aws-signature.ts can be easily transformed into a service).

# Example usage with a POST request

Import this code (class and data model), initialize data model e.g.:

```
let awsSignatureInputData = new AwsSignatureInputData();

awsSignatureInputData.method = 'POST';
awsSignatureInputData.canonicalUri = '/api/example/login/';
awsSignatureInputData.host = 'ec2-example.compute.amazonaws.com';
awsSignatureInputData.region = 'eu-west-1';
awsSignatureInputData.service = '<service>';
awsSignatureInputData.accessKey = '<EXAMPLE_ACCESS_KEY>';
awsSignatureInputData.secretKey = '<EXAMPLE_SECRET_KEY>';
awsSignatureInputData.contentType = 'application/json';
awsSignatureInputData.requestParameters = '{"username":"andrzej","password":"UhR*^sf#("}';
awsSignatureInputData.canonicalQuerystring = '';
```

- requestParameters - the body of a request
- canonicalQuerystring - in case of a GET request, url parameters string

then just call the imported module:

`let signature = awsSignature.generateSignature(awsSignatureInputData);`

then while making a GET/POST request to the EC2 API, add those 3 generated headers.


License: MIT. Please add source information to the code if you would like to reuse it.
