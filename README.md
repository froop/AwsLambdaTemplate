# AwsLambdaTemplate

## Input example

```
{
  "algorithm": "Blowfish",
  "keyCharSet": "0123456789abcdefghijklmnopqrstuvwxyz",
  "plainText": "plain001",
  "cipherText": "dI5r7aoODMRkgH5qX6oTAA==",
  "capacity": 1000000,
  "start": 1
}
```

## Output example

```
{
  "algorithm": "Blowfish",
  "keyCharSet": "0123456789abcdefghijklmnopqrstuvwxyz",
  "plainText": "plain001",
  "cipherText": "dI5r7aoODMRkgH5qX6oTAA==",
  "capacity": 1000000,
  "start": 2000001,
  "keyText": "key01"
}
```

## AWS Step Functions

* ASL

```
{
  "Comment": "Iteration template",
  "StartAt": "MainProcess",
  "States": {
    "MainProcess": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-1:123456789012:function:AwsLambdaTemplate",
      "Next": "CheckProcess"
    },
    "CheckProcess": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.keyText",
          "StringEquals": "",
          "Next": "MainProcess"
        }
      ],
      "Default": "SuccessProcess"
    },
    "SuccessProcess": {
      "Type": "Succeed"
    }
  }
}
```