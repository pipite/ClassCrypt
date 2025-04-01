object Main: TMain
  Left = 0
  Top = 0
  Caption = 'Test application sous un autre compte'
  ClientHeight = 956
  ClientWidth = 412
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnClose = FormClose
  TextHeight = 13
  object Label1: TLabel
    Left = 8
    Top = 88
    Width = 25
    Height = 13
    Caption = 'Login'
  end
  object Label2: TLabel
    Left = 8
    Top = 116
    Width = 35
    Height = 13
    Caption = 'Domain'
  end
  object Label4: TLabel
    Left = 8
    Top = 60
    Width = 52
    Height = 13
    Caption = 'Application'
  end
  object LabelWinCrypt: TLabel
    Left = 8
    Top = 372
    Width = 161
    Height = 13
    Caption = 'Cryptage AES + SHA + Password'
  end
  object LbRSAKey: TLabel
    Left = 8
    Top = 520
    Width = 61
    Height = 13
    Caption = 'LabelRsaKey'
  end
  object Label3: TLabel
    Left = 8
    Top = 178
    Width = 353
    Height = 29
    Caption = 'Cryptage AES + SHA + Password'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -24
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label5: TLabel
    Left = 8
    Top = 399
    Width = 343
    Height = 29
    Caption = 'Cryptage RSA Public/Private AES'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -24
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label6: TLabel
    Left = 8
    Top = 703
    Width = 378
    Height = 29
    Caption = 'RSA Cryptage AES + SHA Password'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -24
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object LbRSACrypt: TLabel
    Left = 8
    Top = 671
    Width = 158
    Height = 13
    Caption = 'Cryptage RSA Public/Private AES'
  end
  object Label7: TLabel
    Left = 8
    Top = 903
    Width = 263
    Height = 13
    Caption = 'Cryptage RSA Public/Private + AES + SHA + Password'
  end
  object Edit1: TEdit
    Left = 80
    Top = 56
    Width = 324
    Height = 21
    TabOrder = 0
    Text = 'C:\Windows\System32\Notepad.exe'
  end
  object Button1: TButton
    Left = 8
    Top = 8
    Width = 396
    Height = 42
    Caption = 'Tester l'#39'application avec un autre compte'
    TabOrder = 1
    OnClick = Button1Click
  end
  object Edit2: TEdit
    Left = 80
    Top = 85
    Width = 324
    Height = 21
    TabOrder = 2
    Text = 'btr-adm'
  end
  object Edit3: TEdit
    Left = 80
    Top = 112
    Width = 324
    Height = 21
    TabOrder = 3
    Text = 'lab.local'
  end
  object EdPassword: TMaskEdit
    Left = 119
    Top = 139
    Width = 225
    Height = 21
    PasswordChar = '*'
    TabOrder = 4
    Text = ''
    OnChange = EdPasswordChange
  end
  object CBVisible: TCheckBox
    Left = 350
    Top = 141
    Width = 54
    Height = 17
    Caption = 'Visible'
    TabOrder = 5
    OnClick = CBVisibleClick
  end
  object BtPassword: TButton
    Left = 8
    Top = 139
    Width = 66
    Height = 21
    Caption = 'Password'
    TabOrder = 6
    OnClick = BtPasswordClick
  end
  object NumberBox1: TNumberBox
    Left = 80
    Top = 139
    Width = 33
    Height = 21
    MinValue = 8.000000000000000000
    MaxValue = 30.000000000000000000
    TabOrder = 7
    Value = 18.000000000000000000
  end
  object BtWinCryptFile: TButton
    Left = 8
    Top = 341
    Width = 185
    Height = 25
    Caption = 'AES Pwd Crypt File'
    TabOrder = 8
    OnClick = BtWinCryptFileClick
  end
  object BtWinDecryptFile: TButton
    Left = 208
    Top = 341
    Width = 196
    Height = 25
    Caption = 'AES Pwd Decrypt File'
    TabOrder = 9
    OnClick = BtWinDecryptFileClick
  end
  object EdExemple: TEdit
    Left = 8
    Top = 213
    Width = 396
    Height = 21
    TabOrder = 10
    Text = 'Ceci est une chaine '#224' crypter en AES + SHA + Password'
  end
  object WinEncrypt: TButton
    Left = 8
    Top = 240
    Width = 185
    Height = 25
    Caption = 'AES Pwd Enccrypt String'
    TabOrder = 11
    OnClick = WinEncryptClick
  end
  object EdWinEncrypt: TEdit
    Left = 8
    Top = 271
    Width = 396
    Height = 21
    TabOrder = 12
  end
  object WinDecrypt: TButton
    Left = 208
    Top = 240
    Width = 196
    Height = 25
    Caption = 'AES Pwd Deccrypt String'
    TabOrder = 13
    OnClick = WinDecryptClick
  end
  object EdFilepath: TEdit
    Left = 8
    Top = 314
    Width = 396
    Height = 21
    TabOrder = 14
    Text = 'C:\Local\Dev\Git\ClassCrypt\Proj\Test.png'
  end
  object BtCreateKey: TButton
    Left = 8
    Top = 458
    Width = 121
    Height = 56
    Caption = 'Create RSA Key'
    TabOrder = 15
    OnClick = BtCreateKeyClick
  end
  object BtLoadPublicRsaKey: TButton
    Left = 144
    Top = 489
    Width = 129
    Height = 25
    Caption = 'Import Public RSA Key'
    TabOrder = 16
    OnClick = BtLoadPublicRsaKeyClick
  end
  object BtExportRSAPrivateKey: TButton
    Left = 285
    Top = 458
    Width = 119
    Height = 25
    Caption = 'Export Private Key'
    TabOrder = 17
    OnClick = BtExportRSAPrivateKeyClick
  end
  object BtExportRSAPublicKey: TButton
    Left = 285
    Top = 489
    Width = 119
    Height = 25
    Caption = 'Export Public Key'
    TabOrder = 18
    OnClick = BtExportRSAPublicKeyClick
  end
  object BtRSAPublicKeyEncrypt: TButton
    Left = 8
    Top = 539
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Encrypt'
    TabOrder = 19
    OnClick = BtRSAPublicKeyEncryptClick
  end
  object BtRSAPrivateKeyDecrypt: TButton
    Left = 208
    Top = 539
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey Decrypt'
    TabOrder = 20
    OnClick = BtRSAPrivateKeyDecryptClick
  end
  object BtRSAPublicKeyCryptFile: TButton
    Left = 8
    Top = 640
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Crypt File'
    TabOrder = 21
    OnClick = BtRSAPublicKeyCryptFileClick
  end
  object BtRSAPrivateKeyDeCryptFile: TButton
    Left = 208
    Top = 640
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey DeCrypt File'
    TabOrder = 22
    OnClick = BtRSAPrivateKeyDeCryptFileClick
  end
  object BtLoadPrivateRsaKey: TButton
    Left = 144
    Top = 458
    Width = 129
    Height = 25
    Caption = 'Import Private RSA Key'
    TabOrder = 23
    OnClick = BtLoadPrivateRsaKeyClick
  end
  object EdRSACrypt: TEdit
    Left = 8
    Top = 570
    Width = 396
    Height = 21
    TabOrder = 24
  end
  object EdRSAExemple: TEdit
    Left = 8
    Top = 431
    Width = 396
    Height = 21
    TabOrder = 25
    Text = 'Ceci est une chaine '#224' crypter en RSA Public/Private AES'
  end
  object EdRSAFile: TEdit
    Left = 8
    Top = 613
    Width = 396
    Height = 21
    TabOrder = 26
    Text = 'C:\Local\Dev\Git\ClassCrypt\Proj\Test.png'
  end
  object Button2: TButton
    Left = 8
    Top = 771
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Encrypt'
    TabOrder = 27
  end
  object Button3: TButton
    Left = 208
    Top = 770
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey Decrypt'
    TabOrder = 28
  end
  object Edit4: TEdit
    Left = 8
    Top = 801
    Width = 396
    Height = 21
    TabOrder = 29
  end
  object Edit5: TEdit
    Left = 8
    Top = 845
    Width = 396
    Height = 21
    TabOrder = 30
    Text = 'C:\Local\Dev\Git\ClassCrypt\Proj\Test.png'
  end
  object Button4: TButton
    Left = 208
    Top = 872
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey DeCrypt File'
    TabOrder = 31
  end
  object Button5: TButton
    Left = 8
    Top = 872
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Crypt File'
    TabOrder = 32
  end
  object Edit6: TEdit
    Left = 8
    Top = 738
    Width = 396
    Height = 21
    TabOrder = 33
    Text = 
      'Ceci est une chaine '#224' crypter en RSA Public/Private + AES + SHA ' +
      '+ Password'
  end
end
