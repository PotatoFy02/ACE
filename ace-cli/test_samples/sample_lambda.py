import boto3
import os

s3 = boto3.client('s3')
dynamodb = boto3.client('dynamodb')

def handler(event, context):
    # High confidence — hardcoded bucket name
    obj = s3.get_object(Bucket='my-app-bucket', Key=event['key'])

    # Medium confidence — env var resource
    table = os.environ['TABLE_NAME']
    dynamodb.put_item(TableName=table, Item={'id': {'S': '123'}})

    return obj['Body'].read()