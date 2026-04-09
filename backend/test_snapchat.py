from app import ensemble_predict

url = 'https://www.snapchat.com/web'
result = ensemble_predict(url)

print('URL:', url)
print('Verdict:', result['verdict'])
print('Risk score:', result['risk_score'])
print('LR score:', result['lr_score'])
print('ML score (RF):', result['ml_score'])
print('Features:', result['features'])
print('Indicators:', result['indicators'])
print('Extras:', result['extras'])
