# cryptographic-API-with-KMS
Building a Cryptographic API Using AWS KMS

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/215c3db5-c722-4a8d-b101-49cf8ca0a738)

### Create DynamoDB Table

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/46c5d7af-841b-4305-b3cf-93273e7ecf8b)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/22553e89-f99f-49c8-9400-6b33538b0361)

tables을 생성

### Create KMS

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/4d4b11aa-32cf-4a0b-9937-172da0340d33)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/8723337e-d06a-4934-89b2-5e9c69333cab)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/12c8219f-ddbf-403a-8724-f4ac00329d15)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/cb1b5000-440e-440e-9ce2-469574665389)

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
    table = resource.Table("demo-dynamodb-tables")
    item = {'id': str(uuid.uuid4()), 'text': encrypt_text}
    resp = table.put_item(Item=item)
    return resp

def get_db(resource, uuid):
    table = resource.Table("demo-dynamodb-tables")
    resp = table.get_item(Key={'id': uuid})    
    return resp['Item']['text']

def lambda_handler(event, context):
    # return event
    try:
        session = boto3.session.Session(region_name='ap-northeast-2')
        resource = boto3.resource('dynamodb')
        client = boto3.client('dynamodb')
        
        key_id = 'alias/demo-kms'
        
        if event['plaintext'] != None:
            encrypt_text = encrypt(session, key_id, event['plaintext'])
            put_db(resource, encrypt_text)
            return json.dumps('{"msg": "Put Database is Finished"}')
        else:
            return json.dumps('{"msg": "ERR"}')
        
    except KeyError:
        if event['uuid'] != None:
            response_db = get_db(resource, event['uuid'])
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
                "arn:aws:dynamodb:ap-northeast-2:948216186415:table/demo-dynamodb-tables",
                "arn:aws:dynamodb:*:948216186415:table/*/index/*"
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

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/c44363dc-0313-4e15-9854-8d79e3175809)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/3a86f11f-f755-449e-8fff-2b1617096552)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/aef62aeb-102a-4221-b0bf-be334f5c8a75)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/aa6d6626-ceb1-4f94-aa04-d397a2ca98a9)
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/1cb6dc5c-267a-4ca3-a2c7-638ad1a825fd)

resource가 encrypt인 경우 암호화만 가능하고, decrypt인 경우 복호화만 가능하게 구성
위 방식으로 Decrypt 생성

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/24f833ca-9aa8-42ab-b363-02447316753b)

Deploy한 후 curl 요청

```
curl -sS --location --request POST 'https://d80a08cdhe.execute-api.ap-northeast-2.amazonaws.com/deploy/encrypt' --header 'Content-Type: application/json' --data-raw '{"plaintext": "Welcome To Gongma!!!!!!"}'
```
![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/631e94d9-186f-4a45-a568-9021b56b2dd1)

DynamoDB에 해당 “Welcome To Gongma!!!!!!” 문구가 암호화되서 저장

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/9e47ac50-27dd-4895-ba1c-dd3999ff363f)

데이터를 복호화

```
curl -sS --location --request POST 'https://d80a08cdhe.execute-api.ap-northeast-2.amazonaws.com/deploy/encrypt' --header 'Content-Type: application/json' --data-raw '{"uuid": "97643386-d085-4161-af39-3fe01c4ee94b"}'
```

![Untitled](https://github.com/LeeSeokBln/cryptographic-API-with-KMS/assets/101256150/67ed6026-0fbd-4386-9329-d26adbd5e943)
