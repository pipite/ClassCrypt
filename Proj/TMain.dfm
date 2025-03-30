object Main: TMain
  Left = 0
  Top = 0
  Caption = 'Test application sous un autre compte'
  ClientHeight = 604
  ClientWidth = 387
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnClose = FormClose
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 96
    Width = 25
    Height = 13
    Caption = 'Login'
  end
  object Label2: TLabel
    Left = 16
    Top = 120
    Width = 35
    Height = 13
    Caption = 'Domain'
  end
  object Label4: TLabel
    Left = 16
    Top = 64
    Width = 52
    Height = 13
    Caption = 'Application'
  end
  object LabelWinCrypt: TLabel
    Left = 83
    Top = 479
    Width = 70
    Height = 13
    Caption = 'LabelWinCrypt'
  end
  object LbRSAKey: TLabel
    Left = 83
    Top = 583
    Width = 61
    Height = 13
    Caption = 'LabelRsaKey'
  end
  object Edit1: TEdit
    Left = 80
    Top = 56
    Width = 297
    Height = 21
    TabOrder = 0
    Text = 'C:\Windows\System32\Notepad.exe'
  end
  object Button1: TButton
    Left = 8
    Top = 8
    Width = 369
    Height = 42
    Caption = 'Tester l'#39'application avec un autre compte'
    TabOrder = 1
    OnClick = Button1Click
  end
  object Edit2: TEdit
    Left = 80
    Top = 85
    Width = 249
    Height = 21
    TabOrder = 2
    Text = 'btr-adm'
  end
  object Edit3: TEdit
    Left = 80
    Top = 112
    Width = 249
    Height = 21
    TabOrder = 3
    Text = 'lab.local'
  end
  object EdEncode: TEdit
    Left = 81
    Top = 197
    Width = 249
    Height = 21
    TabOrder = 4
  end
  object EdPassword: TMaskEdit
    Left = 119
    Top = 139
    Width = 210
    Height = 21
    PasswordChar = '*'
    TabOrder = 5
    Text = ''
    OnChange = EdPasswordChange
  end
  object CBVisible: TCheckBox
    Left = 335
    Top = 141
    Width = 97
    Height = 17
    Caption = 'Visible'
    TabOrder = 6
    OnClick = CBVisibleClick
  end
  object BtEncrypt: TButton
    Left = 81
    Top = 224
    Width = 121
    Height = 25
    Caption = 'Enccrypt Password'
    TabOrder = 7
    OnClick = BtEncryptClick
  end
  object EdEncrypt: TEdit
    Left = 81
    Top = 255
    Width = 249
    Height = 21
    TabOrder = 8
  end
  object BtDecrypt: TButton
    Left = 208
    Top = 224
    Width = 121
    Height = 25
    Caption = 'Deccrypt Password'
    TabOrder = 9
    OnClick = BtDecryptClick
  end
  object BtDecode: TButton
    Left = 208
    Top = 166
    Width = 121
    Height = 25
    Caption = 'Decode Password'
    TabOrder = 10
    OnClick = BtDecodeClick
  end
  object BtPassword: TButton
    Left = 8
    Top = 139
    Width = 66
    Height = 21
    Caption = 'Password'
    TabOrder = 11
    OnClick = BtPasswordClick
  end
  object NumberBox1: TNumberBox
    Left = 80
    Top = 139
    Width = 33
    Height = 21
    MinValue = 8.000000000000000000
    MaxValue = 30.000000000000000000
    TabOrder = 12
    Value = 18.000000000000000000
  end
  object BtWinCryptFile: TButton
    Left = 81
    Top = 448
    Width = 121
    Height = 25
    Caption = 'WinCryptFile'
    TabOrder = 13
    OnClick = BtWinCryptFileClick
  end
  object BtWinDecryptFile: TButton
    Left = 208
    Top = 448
    Width = 121
    Height = 25
    Caption = 'WinDecryptFile'
    TabOrder = 14
    OnClick = BtWinDecryptFileClick
  end
  object EdExemple: TEdit
    Left = 81
    Top = 314
    Width = 249
    Height = 21
    TabOrder = 15
    Text = 'Ceci est une chaine '#224' crypter'
  end
  object BtEncode: TButton
    Left = 81
    Top = 166
    Width = 121
    Height = 25
    Caption = 'Encode Password'
    TabOrder = 16
    OnClick = BtEncodeClick
  end
  object WinEncrypt: TButton
    Left = 81
    Top = 341
    Width = 121
    Height = 25
    Caption = 'WinEnccrypt String'
    TabOrder = 17
    OnClick = WinEncryptClick
  end
  object EdWinEncrypt: TEdit
    Left = 81
    Top = 372
    Width = 249
    Height = 21
    TabOrder = 18
  end
  object WinDecrypt: TButton
    Left = 208
    Top = 341
    Width = 121
    Height = 25
    Caption = 'WinDeccrypt String'
    TabOrder = 19
    OnClick = WinDecryptClick
  end
  object EdFilepath: TEdit
    Left = 80
    Top = 421
    Width = 249
    Height = 21
    TabOrder = 20
    Text = 'C:\Local\Dev\Git\ClassCrypt\Proj\Test.png'
  end
  object BtCreateKey: TButton
    Left = 8
    Top = 521
    Width = 153
    Height = 25
    Caption = 'Create RSA 2048 Key pair'
    TabOrder = 21
    OnClick = BtCreateKeyClick
  end
  object BtLoadRsaKey: TButton
    Left = 8
    Top = 552
    Width = 153
    Height = 25
    Caption = 'Import RSA 2048 Key'
    TabOrder = 22
    OnClick = BtLoadRsaKeyClick
  end
  object BtExportRSAPrivateKey: TButton
    Left = 224
    Top = 521
    Width = 153
    Height = 25
    Caption = 'Export RSA Private Key'
    TabOrder = 23
    OnClick = BtExportRSAPrivateKeyClick
  end
  object BtExportRSAPublicKey: TButton
    Left = 224
    Top = 552
    Width = 153
    Height = 25
    Caption = 'Export RSA Public Key'
    TabOrder = 24
    OnClick = BtExportRSAPublicKeyClick
  end
end
