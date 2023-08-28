# Cryptographic Using API AND AWS KMS

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/215c3db5-c722-4a8d-b101-49cf8ca0a738)
<img src="https://github-production-user-asset-6210df.s3.amazonaws.com/101256150/261237266-215c3db5-c722-4a8d-b101-49cf8ca0a738.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230828%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230828T001222Z&X-Amz-Expires=300&X-Amz-Signature=fb859476bf69e656164f10fd6b887369095a7f4c1c5ca06032a9614cbbab233c&X-Amz-SignedHeaders=host&actor_id=101256150&key_id=0&repo_id=679556584">
### Create DynamoDB Table

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/9f1e0c6d-9896-4ec6-9d91-a1641705812f)


tables을 생성

### Create KMS

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/a7689013-7aad-4faa-9322-433e9dd30252)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/e6c3c043-487d-4890-b51d-b541220c5d66)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/156d8602-e77b-4f08-93dd-cc7c376b6569)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/d625de0a-5943-4491-857d-9bcf15158ff9)



나머지는 기본 값으로 생성

### 나머지는 기본 값으로 생성
```
import boto3
import base64
import json
import uuid

def encrypt(session, key_id, Plaintext):
    kms = session.client('kms')
    stuff = kms.encrypt(
        KeyId=key_id, 
        Plaintext=Plaintext
    )
    binary_encrypted = stuff[u'CiphertextBlob']
    encrypted_password = base64.b64encode(binary_encrypted)

    return encrypted_password.decode()
    
def decrypt(session, encrypted_password):
    client = session.client('kms')
    plaintext = client.decrypt(
        CiphertextBlob=bytes(base64.b64decode(encrypted_password))
    )
    return plaintext["Plaintext"]

def put_db(resource, encrypt_text):
    table = resource.Table("db-table")
    item = {'id': str(uuid.uuid4()), 'text': encrypt_text}
    resp = table.put_item(Item=item)
    return resp

def get_db(resource, uuid):
    table = resource.Table("db-table")
    resp = table.get_item(Key={'id': uuid})    
    return resp['Item']['text']

def lambda_handler(event, context):
    session = boto3.session.Session(region_name='ap-northeast-2')
    resource = boto3.resource('dynamodb')
    client = boto3.client('dynamodb')
    key_id = 'alias/seokbin-kms'
    
    plaintext = event.get('plaintext')
    uuid_val = event.get('uuid')

    if plaintext:
        encrypt_text = encrypt(session, key_id, plaintext)
        put_db(resource, encrypt_text)
        return json.dumps('{"msg": "Put Database is Finished"}')
    elif uuid_val:
        response_db = get_db(resource, uuid_val)
        return decrypt(session, response_db)
    else:
        return json.dumps('{"msg": "ERR"}')

```
해당 Lambda 함수에는 아래와 같은 권한을 부여
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:Scan",
                "dynamodb:Query",
                "dynamodb:UpdateItem"
            ],
            "Resource": [
                "arn:aws:dynamodb:ap-northeast-2:<계정 ID>:table/db-table",
                "arn:aws:dynamodb:*:<계정 ID>:table/*/index/*"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt"
            ],
            "Resource": "*"
        }
    ]
}
```

### Create API Gateway

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/06ffcf11-d6aa-4b7e-a5cb-8e09fc4291e4)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/d9fab148-a37e-4f24-90fe-8e18294e5c0d)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/5ecf5f05-822f-41c6-ac02-59c27eead9a8)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/c8b9ce4a-3fb9-4a74-9312-7a393b7c2963)

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/2076c168-205d-4442-aca6-7e088ed45791)


resource가 encrypt인 경우 암호화만 가능하고, decrypt인 경우 복호화만 가능하게 구성
위 방식으로 Decrypt 생성

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/ef568fcb-7b40-403e-9a8e-424f7875872a)


Deploy한 후 curl 요청

```
curl -sS --location --request POST 'https://nfbfptsbjg.execute-api.ap-northeast-2.amazonaws.com/prod/encrypt' --header 'Content-Type: application/json' --data-raw '{"plaintext": "MY API TEST"}'
```
![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/f3adc2ed-7f58-48de-b547-52a737bd1443)


DynamoDB에 해당 “MY API TEST” 문구가 암호화되서 저장

![image](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/762203e9-f4b3-48bf-a7b7-9942b367675d)



데이터를 복호화

```
curl -sS --location --request POST 'https://nfbfptsbjg.execute-api.ap-northeast-2.amazonaws.com/prod/decrtpt' --header 'Content-Type: application/json' --data-raw '{"uuid": "d8a90883-89aa-48df-9b1d-71fb3853620f"}'
```
``` 


    MY API TEST


 ```

