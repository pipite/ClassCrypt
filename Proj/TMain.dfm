object Main: TMain
  Left = 0
  Top = 0
  Caption = 'Test application sous un autre compte'
  ClientHeight = 670
  ClientWidth = 405
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
    Left = 8
    Top = 372
    Width = 92
    Height = 13
    Caption = 'LabelRSAPwdCrypt'
  end
  object LbRSAKey: TLabel
    Left = 153
    Top = 496
    Width = 61
    Height = 13
    Caption = 'LabelRsaKey'
  end
  object Label3: TLabel
    Left = 8
    Top = 178
    Width = 300
    Height = 29
    Caption = 'Cryptage AES Password AES'
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
    Width = 222
    Height = 29
    Caption = 'RSA Assymetric Keys'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -24
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label6: TLabel
    Left = 8
    Top = 522
    Width = 302
    Height = 29
    Caption = 'Cryptage AES Password RSA'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -24
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
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
  object EdPassword: TMaskEdit
    Left = 119
    Top = 139
    Width = 210
    Height = 21
    PasswordChar = '*'
    TabOrder = 4
    Text = ''
    OnChange = EdPasswordChange
  end
  object CBVisible: TCheckBox
    Left = 335
    Top = 141
    Width = 97
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
    Width = 145
    Height = 25
    Caption = 'AES Pwd Crypt File'
    TabOrder = 8
    OnClick = BtWinCryptFileClick
  end
  object BtWinDecryptFile: TButton
    Left = 159
    Top = 341
    Width = 143
    Height = 25
    Caption = 'AES Pwd Decrypt File'
    TabOrder = 9
    OnClick = BtWinDecryptFileClick
  end
  object EdExemple: TEdit
    Left = 8
    Top = 213
    Width = 393
    Height = 21
    TabOrder = 10
    Text = 'Ceci est une chaine '#224' crypter'
  end
  object WinEncrypt: TButton
    Left = 8
    Top = 240
    Width = 145
    Height = 25
    Caption = 'AES Pwd Enccrypt String'
    TabOrder = 11
    OnClick = WinEncryptClick
  end
  object EdWinEncrypt: TEdit
    Left = 8
    Top = 271
    Width = 393
    Height = 21
    TabOrder = 12
  end
  object WinDecrypt: TButton
    Left = 159
    Top = 240
    Width = 143
    Height = 25
    Caption = 'AES Pwd Deccrypt String'
    TabOrder = 13
    OnClick = WinDecryptClick
  end
  object EdFilepath: TEdit
    Left = 8
    Top = 314
    Width = 389
    Height = 21
    TabOrder = 14
    Text = 'C:\Local\Dev\Git\ClassCrypt\Proj\Test.png'
  end
  object BtCreateKey: TButton
    Left = 8
    Top = 434
    Width = 121
    Height = 56
    Caption = 'Create RSA Key'
    TabOrder = 15
    OnClick = BtCreateKeyClick
  end
  object BtLoadPublicRsaKey: TButton
    Left = 144
    Top = 465
    Width = 129
    Height = 25
    Caption = 'Import Public RSA Key'
    TabOrder = 16
    OnClick = BtLoadPublicRsaKeyClick
  end
  object BtExportRSAPrivateKey: TButton
    Left = 279
    Top = 434
    Width = 119
    Height = 25
    Caption = 'Export Private Key'
    TabOrder = 17
    OnClick = BtExportRSAPrivateKeyClick
  end
  object BtExportRSAPublicKey: TButton
    Left = 279
    Top = 465
    Width = 119
    Height = 25
    Caption = 'Export Public Key'
    TabOrder = 18
    OnClick = BtExportRSAPublicKeyClick
  end
  object Button2: TButton
    Left = 25
    Top = 600
    Width = 75
    Height = 25
    Caption = 'Button2'
    TabOrder = 19
  end
  object Button3: TButton
    Left = 128
    Top = 600
    Width = 75
    Height = 25
    Caption = 'Button3'
    TabOrder = 20
  end
  object Button4: TButton
    Left = 227
    Top = 600
    Width = 75
    Height = 25
    Caption = 'Button4'
    TabOrder = 21
  end
  object Button5: TButton
    Left = 322
    Top = 600
    Width = 75
    Height = 25
    Caption = 'Button5'
    TabOrder = 22
  end
  object BtLoadPrivateRsaKey: TButton
    Left = 144
    Top = 434
    Width = 129
    Height = 25
    Caption = 'Import Private RSA Key'
    TabOrder = 23
    OnClick = BtLoadPrivateRsaKeyClick
  end
end
