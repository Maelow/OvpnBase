#Requires -Version 5.1
param([switch]$SmokeTest)
# OvpnBase — річне оновлення OpenVPN (MikroTik): сертифікати, порт, профілі, архіви.
# Запуск: Start-OvpnBase.bat

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $exe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"") + $(if ($SmokeTest) { @('-SmokeTest') } else { @() })
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Windows.Forms

$ModulePaths = @('RouterOsApi', 'Checks', 'CertOps', 'Profile', 'Archive', 'Workflow', 'Setup') | ForEach-Object { Join-Path $Root "lib\$_.psm1" }
try { foreach ($m in $ModulePaths) { Import-Module $m -Force -DisableNameChecking } }
catch { [System.Windows.MessageBox]::Show("Не вдалося завантажити модулі: $($_.Exception.Message)", 'OvpnBase', 'OK', 'Error') | Out-Null; return }

$global:OvpnSync = [hashtable]::Synchronized(@{
        Log   = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
        Steps = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    })

$SettingsPath = Join-Path $Root 'settings.json'
$LogDir = Join-Path $Root 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$script:LogFile = Join-Path $LogDir ("ovpnbase-{0:yyyyMMdd}.log" -f (Get-Date))

# ====================================================================== XAML
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OvpnBase — річне оновлення VPN" Width="1280" Height="860" MinWidth="1060" MinHeight="680"
        WindowStartupLocation="CenterScreen" Background="#0E1116" FontFamily="Segoe UI" FontSize="13" Foreground="#E6EAF0"
        UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <SolidColorBrush x:Key="BgBrush" Color="#0E1116"/>
    <SolidColorBrush x:Key="SideBrush" Color="#12161D"/>
    <SolidColorBrush x:Key="CardBrush" Color="#171C24"/>
    <SolidColorBrush x:Key="Card2Brush" Color="#1E2530"/>
    <SolidColorBrush x:Key="LineBrush" Color="#2A3240"/>
    <SolidColorBrush x:Key="TextBrush" Color="#E6EAF0"/>
    <SolidColorBrush x:Key="MutedBrush" Color="#8B95A5"/>
    <SolidColorBrush x:Key="AccentBrush" Color="#4F8CFF"/>
    <SolidColorBrush x:Key="AccentHoverBrush" Color="#6A9EFF"/>
    <SolidColorBrush x:Key="OkBrush" Color="#3DDC97"/>
    <SolidColorBrush x:Key="WarnBrush" Color="#FFB547"/>
    <SolidColorBrush x:Key="FailBrush" Color="#FF5C6C"/>
    <SolidColorBrush x:Key="InfoBrush" Color="#7AA2F7"/>

    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource TextBrush}"/></Style>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,0,0,4"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="FontSize" Value="12"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style x:Key="H2" TargetType="TextBlock">
      <Setter Property="FontSize" Value="15"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Margin" Value="0,0,0,14"/>
    </Style>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{StaticResource CardBrush}"/><Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/><Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="18"/><Setter Property="Margin" Value="0,0,0,14"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource Card2Brush}"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/><Setter Property="CaretBrush" Value="{StaticResource TextBrush}"/>
      <Setter Property="SelectionBrush" Value="{StaticResource AccentBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource AccentBrush}"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.5"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="{StaticResource Card2Brush}"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/><Setter Property="CaretBrush" Value="{StaticResource TextBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource AccentBrush}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Card2Brush}"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,8"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#283141"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{StaticResource AccentBrush}"/><Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
      <Setter Property="Foreground" Value="White"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{StaticResource AccentHoverBrush}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3A1E24"/><Setter Property="BorderBrush" Value="#7A2E3A"/><Setter Property="Foreground" Value="#FFC2CA"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#4A242C"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Small" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Padding" Value="10,5"/><Setter Property="FontSize" Value="12"/>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/><Setter Property="Margin" Value="0,4,0,4"/>
    </Style>
    <Style x:Key="Chip" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/><Setter Property="Margin" Value="0,0,8,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="{StaticResource Card2Brush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="1"
                    CornerRadius="14" Padding="14,5">
              <ContentPresenter HorizontalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource AccentBrush}"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="StatusGlyph" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource InfoBrush}"/><Setter Property="FontFamily" Value="Segoe UI Symbol"/>
      <Setter Property="FontSize" Value="14"/><Setter Property="HorizontalAlignment" Value="Center"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="ToolTip" Value="Інформація — довідково, дій не потрібно"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="OK"><Setter Property="Foreground" Value="{StaticResource OkBrush}"/><Setter Property="ToolTip" Value="Гаразд — перевірку пройдено"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="WARN"><Setter Property="Foreground" Value="{StaticResource WarnBrush}"/><Setter Property="ToolTip" Value="Попередження — працює, але варто звернути увагу"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="FAIL"><Setter Property="Foreground" Value="{StaticResource FailBrush}"/><Setter Property="ToolTip" Value="Помилка — потрібно виправити; критичні блокують зміни"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="RUN"><Setter Property="Foreground" Value="{StaticResource AccentBrush}"/><Setter Property="ToolTip" Value="Виконується"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="SKIP"><Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="ToolTip" Value="Пропущено / неактивно"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="WAIT"><Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="ToolTip" Value="Очікує"/></DataTrigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="Transparent"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="RowBackground" Value="{StaticResource CardBrush}"/><Setter Property="AlternatingRowBackground" Value="#1A1F28"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource LineBrush}"/><Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="AutoGenerateColumns" Value="False"/><Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/><Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="RowHeaderWidth" Value="0"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{StaticResource Card2Brush}"/><Setter Property="Foreground" Value="{StaticResource MutedBrush}"/>
      <Setter Property="Padding" Value="8,7"/><Setter Property="BorderThickness" Value="0,0,0,1"/><Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="8,6"><ContentPresenter VerticalAlignment="Top"/></Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#24314A"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="ToolTip">
      <Setter Property="Background" Value="#232A36"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/><Setter Property="Padding" Value="10,6"/>
      <Setter Property="MaxWidth" Value="560"/>
      <Setter Property="ContentTemplate">
        <Setter.Value><DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap"/></DataTemplate></Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Wrap" TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/></Style>
    <Style x:Key="WrapWarn" TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="Foreground" Value="{StaticResource WarnBrush}"/></Style>

    <Style TargetType="ListBox">
      <Setter Property="Background" Value="{StaticResource Card2Brush}"/><Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{StaticResource LineBrush}"/><Setter Property="Padding" Value="4"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="{StaticResource TextBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Bd" CornerRadius="5" Padding="10,6" Background="Transparent"><ContentPresenter/></Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#252D3A"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="Bd" Property="Background" Value="#2A3F66"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Nav" TargetType="TabItem">
      <Setter Property="Foreground" Value="{StaticResource MutedBrush}"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" Margin="10,2" Padding="12,10" CornerRadius="8" Background="Transparent">
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="30"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Border x:Name="Badge" Width="22" Height="22" CornerRadius="11" Background="{StaticResource Card2Brush}" HorizontalAlignment="Left">
                  <TextBlock Text="{TemplateBinding Tag}" FontSize="11" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="{StaticResource MutedBrush}"/>
                </Border>
                <ContentPresenter Grid.Column="1" ContentSource="Header" VerticalAlignment="Center"/>
              </Grid>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#1A2029"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1D2940"/>
                <Setter TargetName="Badge" Property="Background" Value="{StaticResource AccentBrush}"/>
                <Setter Property="Foreground" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="64"/><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="190" MinHeight="80"/>
    </Grid.RowDefinitions>

    <!-- header -->
    <Border Grid.Row="0" Background="{StaticResource SideBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,0,0,1">
      <Grid Margin="20,0">
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="34" Height="34" CornerRadius="9" Background="{StaticResource AccentBrush}" Margin="0,0,12,0">
            <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <StackPanel VerticalAlignment="Center">
            <TextBlock Text="OvpnBase" FontSize="17" FontWeight="SemiBold"/>
            <TextBlock Text="Річне оновлення OpenVPN: сертифікати · порт · профілі · архіви" Style="{StaticResource Hint}"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
          <ProgressBar x:Name="PbBusy" Width="160" Height="4" IsIndeterminate="True" Visibility="Collapsed" Foreground="{StaticResource AccentBrush}" Background="{StaticResource Card2Brush}" BorderThickness="0"/>
          <TextBlock x:Name="TbBusy" Margin="10,0,0,0" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
        </StackPanel>
        <Border Grid.Column="2" Background="{StaticResource Card2Brush}" CornerRadius="14" Padding="12,6" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="StatusDot" Width="9" Height="9" Fill="{StaticResource MutedBrush}" Margin="0,0,8,0" VerticalAlignment="Center"/>
            <TextBlock x:Name="TbStatus" Text="Не підключено" FontSize="12"/>
          </StackPanel>
        </Border>
      </Grid>
    </Border>

    <!-- body -->
    <TabControl x:Name="Tabs" Grid.Row="1" Background="Transparent" BorderThickness="0" Padding="0">
      <TabControl.Template>
        <ControlTemplate TargetType="TabControl">
          <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Background="{StaticResource SideBrush}" BorderBrush="{StaticResource LineBrush}" BorderThickness="0,0,1,0">
              <DockPanel>
                <TextBlock DockPanel.Dock="Bottom" Margin="22,0,22,16" Style="{StaticResource Hint}" Text="Паролі не зберігаються на диску і не пишуться в журнал."/>
                <StackPanel IsItemsHost="True" Margin="0,14,0,0"/>
              </DockPanel>
            </Border>
            <ContentPresenter Grid.Column="1" ContentSource="SelectedContent"/>
          </Grid>
        </ControlTemplate>
      </TabControl.Template>

      <!-- 1. connection -->
      <TabItem Header="Підключення" Tag="1" Style="{StaticResource Nav}">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="24,20,24,10" MaxWidth="900" HorizontalAlignment="Left">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="MikroTik API" Style="{StaticResource H2}"/>
              <Grid>
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="120"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition/><RowDefinition Height="12"/><RowDefinition/></Grid.RowDefinitions>
                <StackPanel><TextBlock Text="Адреса роутера" Style="{StaticResource Lbl}"/><TextBox x:Name="TbRouter"/></StackPanel>
                <StackPanel Grid.Column="2"><TextBlock Text="Порт API" Style="{StaticResource Lbl}"/><TextBox x:Name="TbApiPort" Text="8728"/></StackPanel>
                <StackPanel Grid.Row="2"><TextBlock Text="Логін" Style="{StaticResource Lbl}"/><TextBox x:Name="TbApiUser"/></StackPanel>
                <StackPanel Grid.Row="2" Grid.Column="2" Grid.ColumnSpan="1"/>
              </Grid>
              <TextBlock Text="Пароль" Style="{StaticResource Lbl}" Margin="0,12,0,4"/>
              <PasswordBox x:Name="PbApiPass"/>
              <StackPanel Orientation="Horizontal" Margin="0,18,0,0">
                <Button x:Name="BtnConnect" Style="{StaticResource Primary}" Content="Підключитись і перевірити"/>
              </StackPanel>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="Вимоги" Style="{StaticResource H2}"/>
              <TextBlock Style="{StaticResource Hint}" Text="• API-сервіс (8728) доступний з цього ПК; RouterOS 7.17+."/>
              <TextBlock Style="{StaticResource Hint}" Text="• Група користувача API має політики: api, read, write, test, ftp (читання файлів), sensitive (експорт ключа)."/>
              <TextBlock Style="{StaticResource Hint}" Text="• Zero Trust не змінюється: новий порт додається лише в правило з src-address-list=MGMT_Allow."/>
              <TextBlock Style="{StaticResource Hint}" Text="• Перед змінами показується повний перелік команд для підтвердження."/>
            </StackPanel>
          </Border>
        </StackPanel></ScrollViewer>
      </TabItem>

      <!-- 2. diagnostics -->
      <TabItem x:Name="TabDiag" Header="Діагностика" Tag="2" Style="{StaticResource Nav}">
        <Grid Margin="24,20,24,10">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid Margin="0,0,0,14">
            <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <StackPanel Orientation="Horizontal">
              <Border Background="#163326" CornerRadius="14" Padding="12,5" Margin="0,0,8,0" ToolTip="Гаразд — перевірку пройдено"><TextBlock x:Name="TbSumOk" Foreground="{StaticResource OkBrush}" Text="✔ 0"/></Border>
              <Border Background="#3A2D14" CornerRadius="14" Padding="12,5" Margin="0,0,8,0" ToolTip="Попередження — працює, але варто звернути увагу"><TextBlock x:Name="TbSumWarn" Foreground="{StaticResource WarnBrush}" Text="⚠ 0"/></Border>
              <Border Background="#3A1A20" CornerRadius="14" Padding="12,5" Margin="0,0,8,0" ToolTip="Помилка — потрібно виправити; критичні блокують зміни"><TextBlock x:Name="TbSumFail" Foreground="{StaticResource FailBrush}" Text="✖ 0"/></Border>
              <Border Background="#1A2540" CornerRadius="14" Padding="12,5" Margin="0,0,8,0" ToolTip="Інформація — довідково, дій не потрібно"><TextBlock x:Name="TbSumInfo" Foreground="{StaticResource InfoBrush}" Text="ℹ 0"/></Border>
              <TextBlock x:Name="TbDiagTime" Style="{StaticResource Hint}" VerticalAlignment="Center" Margin="8,0,0,0"/>
            </StackPanel>
            <StackPanel Grid.Column="2" Orientation="Horizontal">
              <CheckBox x:Name="CbOnlyProblems" Content="Лише проблеми" VerticalAlignment="Center" Margin="0,0,14,0"/>
              <Button x:Name="BtnDiagRefresh" Content="Оновити" Style="{StaticResource Small}"/>
              <Button x:Name="BtnDiagCopy" Content="Скопіювати звіт" Style="{StaticResource Small}" Margin="0"/>
            </StackPanel>
          </Grid>
          <Border Grid.Row="1" Style="{StaticResource Card}" Padding="0" Margin="0">
            <DataGrid x:Name="DgDiag">
              <DataGrid.RowStyle>
                <Style TargetType="DataGridRow"><Setter Property="ToolTip" Value="{Binding Tip}"/></Style>
              </DataGrid.RowStyle>
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="" Width="38">
                  <DataGridTemplateColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Icon}" Style="{StaticResource StatusGlyph}"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
                <DataGridTextColumn Header="Група" Binding="{Binding Group}" Width="170" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="Перевірка" Binding="{Binding Name}" Width="230" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="Деталі" Binding="{Binding Detail}" Width="*" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="Що зробити" Binding="{Binding Fix}" Width="260" ElementStyle="{StaticResource WrapWarn}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
        </Grid>
      </TabItem>

      <!-- 3. CA + initial setup -->
      <TabItem x:Name="TabSetup" Header="CA і сервер" Tag="3" Style="{StaticResource Nav}">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="24,20,24,10">
          <Border x:Name="BdSetupBanner" CornerRadius="10" Padding="18,14" Margin="0,0,0,14" BorderThickness="1" Visibility="Collapsed">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <TextBlock x:Name="TbSetupBannerIcon" FontFamily="Segoe UI Symbol" FontSize="22" Margin="0,0,14,0" VerticalAlignment="Center"/>
              <StackPanel Grid.Column="1" VerticalAlignment="Center">
                <TextBlock x:Name="TbSetupBannerTitle" FontSize="15" FontWeight="SemiBold"/>
                <TextBlock x:Name="TbSetupBannerText" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="#C9D1DC"/>
              </StackPanel>
              <Button x:Name="BtnSetupToggle" Grid.Column="2" Style="{StaticResource Small}" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </Grid>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="Стан OpenVPN на роутері" Style="{StaticResource H2}"/>
              <TextBlock x:Name="TbSetupStatus" Style="{StaticResource Hint}" FontFamily="Consolas" Text="Підключіться до роутера."/>
            </StackPanel>
          </Border>
          <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Кореневий CA" Style="{StaticResource H2}"/>
                  <TextBlock x:Name="TbCaStatus" Style="{StaticResource Hint}" Margin="0,0,0,10"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="80"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Ім'я" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCaName"/></StackPanel><StackPanel Grid.Column="2"><TextBlock Text="Common Name" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCaCn"/></StackPanel><StackPanel Grid.Column="4"><TextBlock Text="Днів" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCaDays" Text="3650"/></StackPanel>
                  </Grid>
                  <TextBlock Text="Ключ (лише для нового CA)" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbCa4096" GroupName="ca" Content="RSA 4096" Style="{StaticResource Chip}" IsChecked="True"/>
                    <RadioButton x:Name="RbCa8192" GroupName="ca" Content="RSA 8192" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbCaEc" GroupName="ca" Content="EC P-384" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                  <WrapPanel Margin="0,12,0,0"><Button x:Name="BtnCaTrust" Content="Позначити trusted" Style="{StaticResource Small}"/></WrapPanel>
                  <TextBlock Text="Паскей для backup CA (сертифікат + приватний ключ на ПК)" Style="{StaticResource Lbl}" Margin="0,14,0,4"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <PasswordBox x:Name="PbCaBackup"/>
                    <Button x:Name="BtnCaBackup" Grid.Column="1" Content="Зберегти backup CA" Style="{StaticResource Small}" Margin="8,0,0,0"/>
                  </Grid>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,6,0,0" Text="Backup потрібен, щоб відновити CA після заміни чи скидання роутера (out\ca-backup\). Якщо поле заповнене — backup робиться й під час первинного налаштування."/>
                </StackPanel>
              </Border>
              <Border x:Name="BdSetupSrvCert" Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Серверний сертифікат" Style="{StaticResource H2}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="80"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Ім'я" Style="{StaticResource Lbl}"/><TextBox x:Name="TbSrvCertName"/></StackPanel><StackPanel Grid.Column="2"><TextBlock Text="Common Name" Style="{StaticResource Lbl}"/><TextBox x:Name="TbSrvCn"/></StackPanel><StackPanel Grid.Column="4"><TextBlock Text="Днів" Style="{StaticResource Lbl}"/><TextBox x:Name="TbSrvDays" Text="3650"/></StackPanel>
                  </Grid>
                  <TextBlock Text="Ключ (лише для нового)" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbSrv4096" GroupName="srv" Content="RSA 4096" Style="{StaticResource Chip}" IsChecked="True"/>
                    <RadioButton x:Name="RbSrv8192" GroupName="srv" Content="RSA 8192" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbSrvEc" GroupName="srv" Content="EC P-384" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                </StackPanel>
              </Border>
            </StackPanel>
            <StackPanel x:Name="SpSetupRight" Grid.Column="2">
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Мережа і OpenVPN-сервер" Style="{StaticResource H2}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <Grid.RowDefinitions><RowDefinition/><RowDefinition Height="10"/><RowDefinition/><RowDefinition Height="10"/><RowDefinition/></Grid.RowDefinitions>
                    <StackPanel><TextBlock Text="IP-пул (ім'я)" Style="{StaticResource Lbl}"/><TextBox x:Name="TbPoolName"/></StackPanel><StackPanel Grid.Column="2"><TextBlock Text="Діапазон пулу" Style="{StaticResource Lbl}"/><TextBox x:Name="TbPoolRange"/></StackPanel>
                    <StackPanel Grid.Row="2"><TextBlock Text="PPP-профіль" Style="{StaticResource Lbl}"/><TextBox x:Name="TbProfName"/></StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="2"><TextBlock Text="local-address (IP або ім'я пулу)" Style="{StaticResource Lbl}"/><TextBox x:Name="TbLocalAddr"/></StackPanel>
                    <StackPanel Grid.Row="4"><TextBlock Text="Ім'я сервера" Style="{StaticResource Lbl}"/><TextBox x:Name="TbSrvName"/></StackPanel>
                    <StackPanel Grid.Row="4" Grid.Column="2"><TextBlock Text="DNS для клієнтів (необов'язково)" Style="{StaticResource Lbl}"/><TextBox x:Name="TbDns"/></StackPanel>
                  </Grid>
                  <Grid Margin="0,10,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Порт" Style="{StaticResource Lbl}"/><TextBox x:Name="TbSrvPort"/></StackPanel>
                    <Button x:Name="BtnSetupPort" Grid.Column="1" Content="Запропонувати" Style="{StaticResource Small}" VerticalAlignment="Bottom" Margin="8,0,0,2"/>
                  </Grid>
                  <TextBlock Text="Протокол" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbProtoTcp" GroupName="proto" Content="TCP" Style="{StaticResource Chip}" IsChecked="True"/>
                    <RadioButton x:Name="RbProtoUdp" GroupName="proto" Content="UDP" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                  <TextBlock Text="Перевірка пароля користувача" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbUaPap" GroupName="ua" Content="PAP (RADIUS / NPS)" Style="{StaticResource Chip}" IsChecked="True"/>
                    <RadioButton x:Name="RbUaMs" GroupName="ua" Content="MS-CHAPv2" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0" Text="Сервер: mode=ip, require-client-certificate=yes, TLS only-1.2, aes256-gcm, sha256."/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Zero Trust і RADIUS" Style="{StaticResource H2}"/>
                  <CheckBox x:Name="CbSetupFw" IsChecked="True" Content="Дозволити порт лише через src-address-list=MGMT_Allow (додати в наявне правило або створити перед фінальним drop)"/>
                  <CheckBox x:Name="CbSetupRadius" Content="Увімкнути RADIUS для PPP (якщо ще не налаштовано)" Margin="0,10,0,4"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Адреса RADIUS" Style="{StaticResource Lbl}"/><TextBox x:Name="TbRadAddr"/></StackPanel>
                    <StackPanel Grid.Column="2"><TextBlock Text="Secret" Style="{StaticResource Lbl}"/><PasswordBox x:Name="PbRadSecret"/></StackPanel>
                  </Grid>
                </StackPanel>
              </Border>
            </StackPanel>
          </Grid>
          <Border x:Name="BdSetupRun" Style="{StaticResource Card}">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="380"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Text="Первинне налаштування" Style="{StaticResource H2}"/>
                <WrapPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
                  <Button x:Name="BtnSetupPreview" Content="Переглянути зміни"/>
                  <Button x:Name="BtnSetupRun" Content="Виконати" Style="{StaticResource Primary}" IsEnabled="False"/>
                </WrapPanel>
                <ItemsControl x:Name="IcSetupSteps">
                <ItemsControl.ItemTemplate>
                  <DataTemplate>
                    <Grid Margin="0,0,0,10">
                      <Grid.ColumnDefinitions><ColumnDefinition Width="28"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                      <TextBlock Text="{Binding Glyph}" Style="{StaticResource StatusGlyph}" HorizontalAlignment="Left" VerticalAlignment="Top"/>
                      <StackPanel Grid.Column="1"><TextBlock Text="{Binding Title}"/><TextBlock Text="{Binding Detail}" Style="{StaticResource Hint}"/></StackPanel>
                    </Grid>
                  </DataTemplate>
                </ItemsControl.ItemTemplate>
                </ItemsControl>
              </DockPanel>
              <TextBox x:Name="TbSetupPlan" Grid.Column="2" IsReadOnly="True" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" MinHeight="260"
                       VerticalScrollBarVisibility="Auto" Text="Кожен крок пропускається, якщо об'єкт уже існує. Натисніть «Переглянути зміни»."/>
            </Grid>
          </Border>
        </StackPanel></ScrollViewer>
      </TabItem>

      <!-- 3. parameters -->
      <TabItem x:Name="TabParams" Header="Параметри року" Tag="4" Style="{StaticResource Nav}">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="24,20,24,10">
          <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Рік і термін дії" Style="{StaticResource H2}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="14"/><ColumnDefinition Width="110"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Рік" Style="{StaticResource Lbl}"/><TextBox x:Name="TbYear"/></StackPanel>
                    <StackPanel Grid.Column="2"><TextBlock Text="Днів дії" Style="{StaticResource Lbl}"/><TextBox x:Name="TbDays"/></StackPanel>
                    <StackPanel Grid.Column="4" VerticalAlignment="Bottom" Orientation="Horizontal">
                      <Button x:Name="BtnDaysEoy" Content="До кінця року" Style="{StaticResource Small}"/>
                      <TextBlock x:Name="TbValidTo" Style="{StaticResource Hint}" VerticalAlignment="Center"/>
                    </StackPanel>
                  </Grid>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Сервер і порт" Style="{StaticResource H2}"/>
                  <TextBlock Text="Поточний OpenVPN-сервер (копіюються його налаштування)" Style="{StaticResource Lbl}"/>
                  <ListBox x:Name="LbServers" Height="78"/>
                  <Grid Margin="0,12,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="120"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Новий порт" Style="{StaticResource Lbl}"/><TextBox x:Name="TbPort"/></StackPanel>
                    <Button x:Name="BtnSuggestPort" Grid.Column="1" Content="Запропонувати" Style="{StaticResource Small}" VerticalAlignment="Bottom" Margin="8,0,0,2"/>
                    <StackPanel Grid.Column="3"><TextBlock Text="Ім'я нового сервера" Style="{StaticResource Lbl}"/><TextBox x:Name="TbNewServer"/></StackPanel>
                  </Grid>
                  <TextBlock x:Name="TbPortCheck" Style="{StaticResource Hint}" Margin="0,6,0,0"/>
                  <CheckBox x:Name="CbSchedule" Content="Запланувати вимкнення старого сервера і прибрати його порт" Margin="0,12,0,4"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="140"/><ColumnDefinition Width="14"/><ColumnDefinition Width="90"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Дата (yyyy-MM-dd)" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCutDate"/></StackPanel>
                    <StackPanel Grid.Column="2"><TextBlock Text="Час" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCutTime" Text="03:00"/></StackPanel>
                  </Grid>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Профіль" Style="{StaticResource H2}"/>
                  <TextBlock Text="VPN-хост (remote)" Style="{StaticResource Lbl}"/><TextBox x:Name="TbHost"/>
                  <TextBlock Text="Резервний хост (необов'язково)" Style="{StaticResource Lbl}" Margin="0,10,0,4"/><TextBox x:Name="TbHost2"/>
                  <TextBlock x:Name="TbHostCheck" Style="{StaticResource Hint}" Margin="0,6,0,0"/>
                  <Button x:Name="BtnCheckHost" Content="Перевірити DNS" Style="{StaticResource Small}" HorizontalAlignment="Left" Margin="0,6,0,0"/>
                  <TextBlock Text="Маршрути (по одному в рядку, 192.168.1.0/24)" Style="{StaticResource Lbl}" Margin="0,12,0,4"/>
                  <TextBox x:Name="TbRoutes" AcceptsReturn="True" Height="82" VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
                  <TextBlock Text="Назва підключення (FRIENDLY_NAME)" Style="{StaticResource Lbl}" Margin="0,10,0,4"/><TextBox x:Name="TbFriendly"/>
                  <CheckBox x:Name="CbReadme" Content="Додати в архіви інструкцію для користувачів (README-Windows / README-macOS)" Margin="0,12,0,4"/>
                  <TextBlock Text="Адреса Zero Trust порталу для інструкції (необов'язково)" Style="{StaticResource Lbl}" Margin="0,6,0,4"/><TextBox x:Name="TbPortal" IsEnabled="False"/>
                  <CheckBox x:Name="CbModern" Content="Модернізувати профіль (remote-cert-tls, verify-x509-name, data-ciphers, tls-version-min 1.2)" IsChecked="True" Margin="0,12,0,4"/>
                </StackPanel>
              </Border>
            </StackPanel>

            <StackPanel Grid.Column="2">
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Клієнтський сертифікат" Style="{StaticResource H2}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="140"/><ColumnDefinition Width="14"/><ColumnDefinition Width="70"/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Text="Ім'я на роутері" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCertName"/></StackPanel>
                    <StackPanel Grid.Column="2"><TextBlock Text="Common Name" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCertCn"/></StackPanel>
                    <StackPanel Grid.Column="4"><TextBlock Text="Країна" Style="{StaticResource Lbl}"/><TextBox x:Name="TbCountry"/></StackPanel>
                  </Grid>
                  <TextBlock Text="Ключ" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbK4096" GroupName="key" Content="RSA 4096" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbK8192" GroupName="key" Content="RSA 8192" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbK16384" GroupName="key" Content="RSA 16384" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbKec" GroupName="key" Content="EC P-384" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                  <TextBlock Text="Підпис" Style="{StaticResource Lbl}" Margin="0,12,0,6"/>
                  <WrapPanel>
                    <RadioButton x:Name="RbD256" GroupName="dg" Content="SHA-256" Style="{StaticResource Chip}"/>
                    <RadioButton x:Name="RbD512" GroupName="dg" Content="SHA-512" Style="{StaticResource Chip}"/>
                  </WrapPanel>
                  <TextBlock x:Name="TbKeyHint" Style="{StaticResource Hint}" Margin="0,8,0,0"/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Секрети" Style="{StaticResource H2}"/>
                  <TextBlock Text="Паскей приватного ключа (вводять користувачі при підключенні)" Style="{StaticResource Lbl}"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <PasswordBox x:Name="PbKey1"/><PasswordBox x:Name="PbKey2" Grid.Column="2"/>
                    <Button x:Name="BtnGenKey" Grid.Column="3" Content="Згенерувати" Style="{StaticResource Small}" Margin="8,0,0,0"/>
                  </Grid>
                  <TextBox x:Name="TbKeyShow" IsReadOnly="True" Visibility="Collapsed" Margin="0,6,0,0" FontFamily="Consolas" Foreground="{StaticResource WarnBrush}"/>
                  <TextBlock Text="Пароль до архівів (exe / zip)" Style="{StaticResource Lbl}" Margin="0,14,0,4"/>
                  <Grid>
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <PasswordBox x:Name="PbArc1"/><PasswordBox x:Name="PbArc2" Grid.Column="2"/>
                    <Button x:Name="BtnGenArc" Grid.Column="3" Content="Згенерувати" Style="{StaticResource Small}" Margin="8,0,0,0"/>
                  </Grid>
                  <TextBox x:Name="TbArcShow" IsReadOnly="True" Visibility="Collapsed" Margin="0,6,0,0" FontFamily="Consolas" Foreground="{StaticResource WarnBrush}"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0" Text="Друге поле — підтвердження. Без пробілів і лапок, мінімум 8 символів. Згенеровані значення збережіть у менеджері паролів — програма їх не зберігає."/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}">
                <StackPanel>
                  <TextBlock Text="Вихідні файли" Style="{StaticResource H2}"/>
                  <TextBlock x:Name="TbOutDir" Style="{StaticResource Hint}"/>
                  <CheckBox x:Name="CbBackup" Content="Зробити backup конфігу роутера (/export) перед змінами" IsChecked="True"/>
                  <CheckBox x:Name="CbDeleteOpen" Content="Видалити незашифровані .ovpn після пакування"/>
                  <TextBlock Style="{StaticResource Hint}" Margin="0,6,0,0" Text="Архіви: VPN-РІК.exe (Windows, 7z SFX AES-256), VPN-РІК-macOS-AES.zip (Keka / The Unarchiver), VPN-РІК-macOS.zip (ZipCrypto — відкривається стандартно, слабкий захист). Усередині лише .ovpn (README — якщо увімкнено в «Профіль»)."/>
                </StackPanel>
              </Border>
            </StackPanel>
          </Grid>
        </StackPanel></ScrollViewer>
      </TabItem>

      <!-- 5. users -->
      <TabItem x:Name="TabUsers" Header="Користувачі" Tag="5" Style="{StaticResource Nav}">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="24,20,24,10">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="Режим автентифікації" Style="{StaticResource H2}"/>
              <WrapPanel>
                <RadioButton x:Name="RbModeRadius" GroupName="mode" Content="RADIUS — один спільний сертифікат" Style="{StaticResource Chip}"/>
                <RadioButton x:Name="RbModeLocal" GroupName="mode" Content="Локальні користувачі — сертифікат на кожного" Style="{StaticResource Chip}"/>
              </WrapPanel>
              <TextBlock x:Name="TbModeHint" Style="{StaticResource Hint}" Margin="0,10,0,0"/>
            </StackPanel>
          </Border>
          <Grid x:Name="GrLocal">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Border Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Наявні користувачі (/ppp secret: ovpn / any)" Style="{StaticResource H2}"/>
                <ListBox x:Name="LbUsers" Height="280"/>
                <WrapPanel Margin="0,10,0,0">
                  <Button x:Name="BtnUsersAll" Content="Усі" Style="{StaticResource Small}"/>
                  <Button x:Name="BtnUsersNone" Content="Жодного" Style="{StaticResource Small}"/>
                </WrapPanel>
                <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0" Text="Позначеним випускаються нові сертифікати року; пароль на роутері не змінюється."/>
              </StackPanel>
            </Border>
            <Border Grid.Column="2" Style="{StaticResource Card}">
              <StackPanel>
                <TextBlock Text="Нові користувачі" Style="{StaticResource H2}"/>
                <TextBlock Text="По одному в рядку: логін  або  логін;пароль (без пароля — згенерується)" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="TbNewUsers" AcceptsReturn="True" Height="150" VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
                <Grid Margin="0,10,0,0">
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <StackPanel><TextBlock Text="PPP-профіль нових" Style="{StaticResource Lbl}"/><TextBox x:Name="TbUserProfile"/></StackPanel>
                  <StackPanel Grid.Column="2"><TextBlock Text="Ім'я сертифіката ({user}, {year})" Style="{StaticResource Lbl}"/><TextBox x:Name="TbUserCertTpl"/></StackPanel>
                </Grid>
                <CheckBox x:Name="CbSaveCreds" Content="Зберегти паролі нових користувачів у users\credentials.csv (відкритий текст)" Margin="0,12,0,0"/>
                <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0" Text="Архіви кожного користувача: out\РІК\users\логін\. Паскей ключа і пароль архівів — спільні з вкладки «Параметри року»."/>
              </StackPanel>
            </Border>
          </Grid>
        </StackPanel></ScrollViewer>
      </TabItem>

      <!-- 4. run -->
      <TabItem x:Name="TabRun" Header="Виконання" Tag="6" Style="{StaticResource Nav}">
        <Grid Margin="24,20,24,10">
          <Grid.ColumnDefinitions><ColumnDefinition Width="420"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Border Style="{StaticResource Card}" Margin="0">
            <DockPanel>
              <StackPanel DockPanel.Dock="Top">
                <TextBlock Text="Кроки" Style="{StaticResource H2}"/>
              </StackPanel>
              <StackPanel DockPanel.Dock="Bottom" Margin="0,12,0,0">
                <TextBlock x:Name="TbElapsed" Style="{StaticResource Hint}" Margin="0,0,0,10"/>
                <WrapPanel>
                  <Button x:Name="BtnPreview" Content="Переглянути зміни" Margin="0,0,8,8"/>
                  <Button x:Name="BtnRun" Content="Виконати" Style="{StaticResource Primary}" IsEnabled="False" Margin="0,0,8,8"/>
                  <Button x:Name="BtnOpenOut" Content="Відкрити теку" Margin="0,0,8,8"/>
                </WrapPanel>
              </StackPanel>
              <ItemsControl x:Name="IcSteps">
                <ItemsControl.ItemTemplate>
                  <DataTemplate>
                    <Grid Margin="0,0,0,12">
                      <Grid.ColumnDefinitions><ColumnDefinition Width="28"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                      <TextBlock Text="{Binding Glyph}" Style="{StaticResource StatusGlyph}" HorizontalAlignment="Left" VerticalAlignment="Top"/>
                      <StackPanel Grid.Column="1">
                        <TextBlock Text="{Binding Title}"/>
                        <TextBlock Text="{Binding Detail}" Style="{StaticResource Hint}"/>
                      </StackPanel>
                    </Grid>
                  </DataTemplate>
                </ItemsControl.ItemTemplate>
              </ItemsControl>
            </DockPanel>
          </Border>
          <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
            <DockPanel>
              <TextBlock DockPanel.Dock="Top" Text="План змін (dry-run)" Style="{StaticResource H2}"/>
              <TextBox x:Name="TbPlan" IsReadOnly="True" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                       Text="Натисніть «Переглянути зміни» — тут з'явиться повний перелік команд для роутера та файлів."/>
            </DockPanel>
          </Border>
        </Grid>
      </TabItem>

      <!-- 5. maintenance -->
      <TabItem x:Name="TabMaint" Header="Обслуговування" Tag="7" Style="{StaticResource Nav}">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="24,20,24,10">
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="Клієнтські сертифікати" Style="{StaticResource H2}"/>
              <DataGrid x:Name="DgCerts" MaxHeight="260">
                <DataGrid.Columns>
                  <DataGridTemplateColumn Header="" Width="38">
                    <DataGridTemplateColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Icon}" Style="{StaticResource StatusGlyph}"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTextColumn Header="Ім'я" Binding="{Binding Name}" Width="220"/>
                  <DataGridTextColumn Header="CN" Binding="{Binding CN}" Width="200"/>
                  <DataGridTextColumn Header="Діє до" Binding="{Binding ValidTo}" Width="160"/>
                  <DataGridTextColumn Header="Ключ" Binding="{Binding Key}" Width="110"/>
                  <DataGridTextColumn Header="Стан" Binding="{Binding State}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
              <WrapPanel Margin="0,12,0,0">
                <Button x:Name="BtnCertRevoke" Content="Відкликати" Style="{StaticResource Danger}"/>
                <Button x:Name="BtnCertRemove" Content="Видалити (прострочені / відкликані)" Style="{StaticResource Danger}"/>
              </WrapPanel>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="OpenVPN-сервери" Style="{StaticResource H2}"/>
              <DataGrid x:Name="DgServers" MaxHeight="200">
                <DataGrid.Columns>
                  <DataGridTemplateColumn Header="" Width="38">
                    <DataGridTemplateColumn.CellTemplate><DataTemplate><TextBlock Text="{Binding Icon}" Style="{StaticResource StatusGlyph}"/></DataTemplate></DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTextColumn Header="Ім'я" Binding="{Binding Name}" Width="200"/>
                  <DataGridTextColumn Header="Порт" Binding="{Binding Port}" Width="90"/>
                  <DataGridTextColumn Header="Протокол" Binding="{Binding Proto}" Width="90"/>
                  <DataGridTextColumn Header="Стан" Binding="{Binding State}" Width="120"/>
                  <DataGridTextColumn Header="У правилі MGMT_Allow" Binding="{Binding InRule}" Width="160"/>
                  <DataGridTextColumn Header="Коментар" Binding="{Binding Comment}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
              <WrapPanel Margin="0,12,0,0">
                <Button x:Name="BtnSrvEnable" Content="Увімкнути"/>
                <Button x:Name="BtnSrvDisable" Content="Вимкнути" Style="{StaticResource Danger}"/>
                <Button x:Name="BtnSrvRemovePort" Content="Прибрати порт з правила MGMT_Allow" Style="{StaticResource Danger}"/>
              </WrapPanel>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <TextBlock Text="Заплановані переходи (ovpn-cutover-*)" Style="{StaticResource H2}"/>
              <DataGrid x:Name="DgSched" MaxHeight="160">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Ім'я" Binding="{Binding Name}" Width="200"/>
                  <DataGridTextColumn Header="Запуск" Binding="{Binding When}" Width="200"/>
                  <DataGridTextColumn Header="Опис" Binding="{Binding Comment}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
              <WrapPanel Margin="0,12,0,0"><Button x:Name="BtnSchedRemove" Content="Скасувати" Style="{StaticResource Danger}"/></WrapPanel>
            </StackPanel>
          </Border>
        </StackPanel></ScrollViewer>
      </TabItem>
    </TabControl>

    <GridSplitter Grid.Row="2" Height="5" HorizontalAlignment="Stretch" Background="{StaticResource LineBrush}" ResizeDirection="Rows"/>

    <!-- log -->
    <Grid Grid.Row="3" Background="#0B0E13">
      <Grid.RowDefinitions><RowDefinition Height="32"/><RowDefinition Height="*"/></Grid.RowDefinitions>
      <Grid Margin="16,0">
        <TextBlock Text="Журнал" Style="{StaticResource Lbl}" VerticalAlignment="Center" Margin="0"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
          <Button x:Name="BtnLogClear" Content="Очистити" Style="{StaticResource Small}" Padding="8,2"/>
          <Button x:Name="BtnLogOpen" Content="Файл журналу" Style="{StaticResource Small}" Padding="8,2" Margin="0"/>
        </StackPanel>
      </Grid>
      <TextBox x:Name="TbLog" Grid.Row="1" IsReadOnly="True" FontFamily="Consolas" FontSize="12" Background="#0B0E13" BorderThickness="0"
               Foreground="#B8C2D0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Padding="12,0,12,8"/>
    </Grid>
  </Grid>
</Window>
'@

try {
    $Window = [Windows.Markup.XamlReader]::Parse($xaml)
} catch {
    [System.Windows.MessageBox]::Show("Помилка XAML: $($_.Exception.InnerException.Message)$($_.Exception.Message)", 'OvpnBase', 'OK', 'Error') | Out-Null
    return
}
$ui = @{}
foreach ($m in [regex]::Matches($xaml, 'x:Name="([^"]+)"')) {
    $n = $m.Groups[1].Value
    $el = $Window.FindName($n)
    if ($el) { $ui[$n] = $el }
}

# ====================================================================== state
$script:State = $null
$script:Checks = @()
$script:Tasks = New-Object System.Collections.ArrayList
$script:Busy = $false
$script:LastPlanHash = $null
$script:Steps = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$ui.IcSteps.ItemsSource = $script:Steps
$script:AutoValues = @{}

function Get-Glyph([string]$s) {
    switch ($s) { 'OK' { [string][char]0x2714 } 'WARN' { [string][char]0x26A0 } 'FAIL' { [string][char]0x2716 } 'RUN' { [string][char]0x25B6 } 'SKIP' { [string][char]0x2013 } default { [string][char]0x25CB } }
}

function Reset-Steps {
    $script:Steps.Clear()
    foreach ($d in (Get-OvpnStepDefs)) {
        $script:Steps.Add([pscustomobject]@{ Key = $d.Key; Title = $d.Title; Status = 'WAIT'; Glyph = (Get-Glyph 'WAIT'); Detail = '' })
    }
}
Reset-Steps

$script:SetupSteps = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$ui.IcSetupSteps.ItemsSource = $script:SetupSteps
function Reset-SetupSteps {
    $script:SetupSteps.Clear()
    foreach ($d in (Get-OvpnSetupStepDefs)) {
        $script:SetupSteps.Add([pscustomobject]@{ Key = $d.Key; Title = $d.Title; Status = 'WAIT'; Glyph = (Get-Glyph 'WAIT'); Detail = '' })
    }
}
Reset-SetupSteps

function Update-Step($ev) {
    $col = if ($ev.Key -like 'setup.*') { $script:SetupSteps } else { $script:Steps }
    for ($i = 0; $i -lt $col.Count; $i++) {
        $s = $col[$i]
        if ($s.Key -eq $ev.Key) {
            $st = $ev.Status.ToUpper()
            $col[$i] = [pscustomobject]@{ Key = $s.Key; Title = $s.Title; Status = $st; Glyph = (Get-Glyph $st); Detail = $ev.Detail }
            break
        }
    }
}

# ====================================================================== settings
function Get-DefaultSettings {
    return [ordered]@{
        Router = ''; ApiPort = 8728; ApiUser = ''; AllowList = 'MGMT_Allow'
        VpnHost = ''; VpnHost2 = ''; Routes = @(); FriendlyTpl = 'VPN Connection {year}'; PortalUrl = ''
        CertNameTpl = 'OVPN-CL-{year}'; CertCnTpl = 'CL-{year}'; NewServerTpl = 'ovpn-server-{year}'
        KeySize = '4096'; Digest = 'sha256'; Country = ''; SourceServer = ''; Modern = $true; DeleteOpen = $false; Backup = $true; Schedule = $true; IncludeReadme = $false
        AuthMode = 'radius'; UserCertTpl = 'OVPN-CL-{user}-{year}'; UserProfile = ''; SaveCredentials = $false
    }
}

function Read-Settings {
    $d = Get-DefaultSettings
    # перший запуск: settings.json створюється з шаблону sample-settings.json
    $samplePath = Join-Path $Root 'sample-settings.json'
    if (-not (Test-Path -LiteralPath $SettingsPath) -and (Test-Path -LiteralPath $samplePath)) {
        try { Copy-Item -LiteralPath $samplePath -Destination $SettingsPath; Write-OvpnLog "settings.json створено з sample-settings.json" }
        catch { Write-OvpnLog -Level WARN "Не вдалося створити settings.json: $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $SettingsPath) {
        try {
            $j = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { $d[$p.Name] = $p.Value }
        } catch { Write-OvpnLog -Level WARN "settings.json пошкоджено: $($_.Exception.Message)" }
    }
    # хост і маршрути не задані — пробуємо взяти з профілю попереднього року (sample\*.ovpn)
    if (-not $d.VpnHost -and @($d.Routes).Count -eq 0) {
        $prev = Get-ChildItem -Path (Join-Path $Root 'sample') -Filter *.ovpn -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($prev) {
            try {
                $info = Read-OvpnProfileInfo $prev.FullName
                if ($info.Hosts.Count) { $d.VpnHost = $info.Hosts[0]; if ($info.Hosts.Count -gt 1) { $d.VpnHost2 = $info.Hosts[1] } }
                if ($info.Routes.Count) { $d.Routes = $info.Routes }
                if ($info.FriendlyName) { $d.FriendlyTpl = ($info.FriendlyName -replace '\b20\d\d\b', '{year}') }
                Write-OvpnLog "Хост і маршрути взято з $($prev.Name)"
            } catch { }
        }
    }
    return $d
}

function Save-Settings {
    $s = [ordered]@{
        Router = $ui.TbRouter.Text.Trim(); ApiPort = [int]("0" + $ui.TbApiPort.Text.Trim()); ApiUser = $ui.TbApiUser.Text.Trim(); AllowList = $script:Settings.AllowList
        VpnHost = $ui.TbHost.Text.Trim(); VpnHost2 = $ui.TbHost2.Text.Trim(); Routes = @(Get-RoutesFromUi); PortalUrl = $ui.TbPortal.Text.Trim()
        FriendlyTpl = (Get-Tpl $ui.TbFriendly.Text 'FriendlyTpl'); CertNameTpl = (Get-Tpl $ui.TbCertName.Text 'CertNameTpl')
        CertCnTpl = (Get-Tpl $ui.TbCertCn.Text 'CertCnTpl'); NewServerTpl = (Get-Tpl $ui.TbNewServer.Text 'NewServerTpl')
        KeySize = (Get-KeySize); Digest = (Get-Digest); Country = $ui.TbCountry.Text.Trim()
        SourceServer = (Get-SelectedServerName); Modern = [bool]$ui.CbModern.IsChecked; DeleteOpen = [bool]$ui.CbDeleteOpen.IsChecked
        Backup = [bool]$ui.CbBackup.IsChecked; Schedule = [bool]$ui.CbSchedule.IsChecked; IncludeReadme = [bool]$ui.CbReadme.IsChecked
        AuthMode = (Get-AuthMode); UserCertTpl = $ui.TbUserCertTpl.Text.Trim(); UserProfile = $ui.TbUserProfile.Text.Trim(); SaveCredentials = [bool]$ui.CbSaveCreds.IsChecked
    }
    try { ($s | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8 } catch { Write-OvpnLog -Level WARN "Не вдалося зберегти settings.json: $($_.Exception.Message)" }
}

# Templates: {year} placeholder. If user edited the value, keep literal text with year → template.
function Get-Tpl([string]$Value, [string]$Key) {
    $y = $ui.TbYear.Text.Trim()
    if ($y -and $Value -match [regex]::Escape($y)) { return ($Value -replace [regex]::Escape($y), '{year}') }
    return $script:Settings[$Key]
}
function Expand-Tpl([string]$Tpl, [string]$Year) { return $Tpl.Replace('{year}', $Year) }

# ====================================================================== helpers
function Get-RoutesFromUi { return @($ui.TbRoutes.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
function Get-KeySize {
    if ($ui.RbK4096.IsChecked) { return '4096' }
    if ($ui.RbK8192.IsChecked) { return '8192' }
    if ($ui.RbKec.IsChecked) { return 'secp384r1' }
    return '16384'
}
function Get-Digest { if ($ui.RbD256.IsChecked) { return 'sha256' } return 'sha512' }
function Get-SelectedServerName {
    $i = $ui.LbServers.SelectedItem
    if ($i -and $i.Tag) { return [string]$i.Tag }
    return $script:Settings.SourceServer
}
function Get-YearInt { $y = 0; [void][int]::TryParse($ui.TbYear.Text.Trim(), [ref]$y); return $y }
function Get-OutDir { return (Join-Path $Root ("out\{0}" -f $ui.TbYear.Text.Trim())) }

function New-Secret([int]$Length = 20) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%+=@_-.'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] ($Length * 2)
    do {
        $rng.GetBytes($bytes)
        $s = -join (0..($Length - 1) | ForEach-Object { $chars[(([int]$bytes[2 * $_] -shl 8) -bor $bytes[2 * $_ + 1]) % $chars.Length] })
    } until ($s -cmatch '[A-Z]' -and $s -cmatch '[a-z]' -and $s -match '\d' -and $s -match '[^A-Za-z0-9]')
    return $s
}

function Get-ConnArgs {
    $pass = $ui.PbApiPass.Password
    $port = 0
    if (-not [int]::TryParse($ui.TbApiPort.Text.Trim(), [ref]$port)) { $port = 8728 }
    return @{
        Router = $ui.TbRouter.Text.Trim(); ApiPort = $port; User = $ui.TbApiUser.Text.Trim(); Pass = $pass
        AllowList = $script:Settings.AllowList; VpnHost = $ui.TbHost.Text.Trim(); VpnHost2 = $ui.TbHost2.Text.Trim()
    }
}

function Show-Error([string]$Text) { [System.Windows.MessageBox]::Show($Window, $Text, 'OvpnBase', 'OK', 'Error') | Out-Null }
function Show-Info([string]$Text) { [System.Windows.MessageBox]::Show($Window, $Text, 'OvpnBase', 'OK', 'Information') | Out-Null }

function Show-Confirm([string]$Title, [string]$Text, [string]$OkText = 'Підтвердити', [switch]$Danger) {
    $dx = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="760" Height="520" WindowStartupLocation="CenterOwner" Background="#171C24" FontFamily="Segoe UI" ResizeMode="CanResizeWithGrip">
  <Grid Margin="20">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock x:Name="T" FontSize="16" FontWeight="SemiBold" Foreground="#E6EAF0" Margin="0,0,0,12"/>
    <TextBox x:Name="B" Grid.Row="1" IsReadOnly="True" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
             Background="#0E1116" Foreground="#D0D7E2" BorderBrush="#2A3240" Padding="10"/>
    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="No" Content="Скасувати" Padding="16,8" Margin="0,0,10,0" IsCancel="True"/>
      <Button x:Name="Yes" Padding="16,8" Foreground="White" FontWeight="SemiBold"/>
    </StackPanel>
  </Grid>
</Window>
'@
    $w = [Windows.Markup.XamlReader]::Parse($dx)
    $w.Owner = $Window
    $w.Title = $Title
    $w.FindName('T').Text = $Title
    $w.FindName('B').Text = $Text
    $yes = $w.FindName('Yes'); $yes.Content = $OkText
    $yes.Background = if ($Danger) { [Windows.Media.Brushes]::IndianRed } else { New-Object Windows.Media.SolidColorBrush ([Windows.Media.Color]::FromRgb(0x4F, 0x8C, 0xFF)) }
    $yes.Add_Click({ $w.DialogResult = $true }.GetNewClosure())
    return [bool]$w.ShowDialog()
}

# ====================================================================== background tasks
$script:BusyControls = @('BtnSetupPreview', 'BtnSetupPort', 'BtnConnect', 'BtnDiagRefresh', 'BtnPreview', 'BtnRun', 'BtnCertRevoke', 'BtnCertRemove', 'BtnSrvEnable', 'BtnSrvDisable', 'BtnSrvRemovePort', 'BtnSchedRemove', 'BtnSuggestPort')

function Set-Busy([bool]$On, [string]$Text = '') {
    $script:Busy = $On
    $ui.PbBusy.Visibility = if ($On) { 'Visible' } else { 'Collapsed' }
    $ui.TbBusy.Text = $Text
    foreach ($n in $script:BusyControls) { if ($n -ne 'BtnRun') { $ui[$n].IsEnabled = -not $On } }
    if ($On) { $ui.BtnRun.IsEnabled = $false; $ui.BtnSetupRun.IsEnabled = $false; $ui.BtnCaTrust.IsEnabled = $false; $ui.BtnCaBackup.IsEnabled = $false }
    else { $ui.BtnRun.IsEnabled = ($null -ne $script:LastPlanHash); $ui.BtnSetupRun.IsEnabled = ($null -ne $script:SetupPlanHash); Update-SetupUi }
}

function Start-Bg {
    param([string]$Title, [string]$Script, [hashtable]$Arg, [scriptblock]$OnDone)
    if ($script:Busy) { return }
    Set-Busy $true $Title
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    try { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass } catch { }
    [void]$iss.ImportPSModule([string[]]$ModulePaths)
    $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry 'OvpnSync', $global:OvpnSync, ''))
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script).AddArgument($Arg)
    $h = $ps.BeginInvoke()
    [void]$script:Tasks.Add(@{ PS = $ps; H = $h; RS = $rs; OnDone = $OnDone; Title = $Title; Start = (Get-Date) })
}

# Standard router job: connect → <op> → refresh state+checks.
function Start-RouterJob {
    param([string]$Title, [string]$Op = '', [hashtable]$Extra = @{}, [scriptblock]$OnDone)
    $a = Get-ConnArgs
    foreach ($k in $Extra.Keys) { $a[$k] = $Extra[$k] }
    if (-not $a.Router -or -not $a.User) { Show-Error 'Вкажіть адресу роутера і логін API на вкладці «Підключення».'; return }
    $script = @"
param(`$A)
`$ErrorActionPreference = 'Stop'
`$c = Connect-RouterOs -Address `$A.Router -Port `$A.ApiPort -User `$A.User -Password `$A.Pass
try {
    `$opResult = `$null
    $Op
    Write-OvpnLog 'Зчитування стану роутера…'
    `$st = Get-RouterState -Connection `$c -AllowList `$A.AllowList
    `$ck = Test-RouterState -State `$st -VpnHost `$A.VpnHost -VpnHost2 `$A.VpnHost2
    @{ State = `$st; Checks = `$ck; OpResult = `$opResult }
} finally { Disconnect-RouterOs `$c }
"@
    Start-Bg -Title $Title -Script $script -Arg $a -OnDone $OnDone
}

function Get-InnerMessage($err) {
    $e = $err
    if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
    while ($e.InnerException -and ($e -is [System.Management.Automation.MethodInvocationException] -or $e.Message -match 'Exception calling')) { $e = $e.InnerException }
    return $e.Message
}

$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:Timer.Add_Tick({
        $line = $null
        $sb = New-Object System.Text.StringBuilder
        while ($global:OvpnSync.Log.TryDequeue([ref]$line)) { [void]$sb.AppendLine($line) }
        if ($sb.Length) {
            $ui.TbLog.AppendText($sb.ToString()); $ui.TbLog.ScrollToEnd()
            try { [System.IO.File]::AppendAllText($script:LogFile, $sb.ToString(), [System.Text.Encoding]::UTF8) } catch { }
        }
        $ev = $null
        while ($global:OvpnSync.Steps.TryDequeue([ref]$ev)) { Update-Step $ev }

        foreach ($t in @($script:Tasks)) {
            $ui.TbBusy.Text = "{0} · {1:mm\:ss}" -f $t.Title, ((Get-Date) - $t.Start)
            if (-not $t.H.IsCompleted) { continue }
            $res = $null; $err = $null
            try { $res = $t.PS.EndInvoke($t.H) } catch { $err = $_ }
            foreach ($er in $t.PS.Streams.Error) { Write-OvpnLog -Level WARN "$($er.Exception.Message)" }
            try { $t.PS.Dispose(); $t.RS.Close(); $t.RS.Dispose() } catch { }
            [void]$script:Tasks.Remove($t)
            Set-Busy $false
            $out = $null
            if ($res -and $res.Count -gt 0) { $out = $res[$res.Count - 1]; if ($out -is [psobject] -and $out.BaseObject) { $out = $out.BaseObject } }
            if ($err) { Write-OvpnLog -Level ERROR (Get-InnerMessage $err) }
            try { & $t.OnDone $out $err } catch { Write-OvpnLog -Level ERROR "UI: $($_.Exception.Message)" }
        }
    })
$script:Timer.Start()

# ====================================================================== render state
function Show-Checks {
    $all = @($script:Checks)
    $ui.TbSumOk.Text = "$([char]0x2714) $(@($all | Where-Object { $_.Status -eq 'OK' }).Count)"
    $ui.TbSumWarn.Text = "$([char]0x26A0) $(@($all | Where-Object { $_.Status -eq 'WARN' }).Count)"
    $ui.TbSumFail.Text = "$([char]0x2716) $(@($all | Where-Object { $_.Status -eq 'FAIL' }).Count)"
    $ui.TbSumInfo.Text = "$([char]0x2139) $(@($all | Where-Object { $_.Status -eq 'INFO' }).Count)"
    $items = if ($ui.CbOnlyProblems.IsChecked) { @($all | Where-Object { $_.Status -in @('WARN', 'FAIL') }) } else { $all }
    $ui.DgDiag.ItemsSource = $items
}

function Show-State {
    $st = $script:State
    if (-not $st) { return }
    $ver = Get-RosVal $st.Resource 'version'
    $ui.TbStatus.Text = "$($st.Identity) · RouterOS $ver · $($ui.TbApiUser.Text)@$($ui.TbRouter.Text)"
    $fails = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $ui.StatusDot.Fill = if ($fails) { $Window.FindResource('WarnBrush') } else { $Window.FindResource('OkBrush') }
    $ui.TbDiagTime.Text = "Оновлено {0:HH:mm:ss}" -f $st.CollectedAt

    # servers list (keep selection)
    $sel = Get-SelectedServerName
    $ui.LbServers.Items.Clear()
    $zt = @{}
    foreach ($s in $st.Servers) {
        $en = -not (Test-RosTrue $s['disabled'])
        $it = New-Object System.Windows.Controls.ListBoxItem
        $it.Content = "{0}  ·  {1}/{2}  ·  {3}" -f $s['name'], $s['protocol'], $s['port'], $(if ($en) { 'увімкнено' } else { 'вимкнено' })
        $it.Tag = $s['name']
        [void]$ui.LbServers.Items.Add($it)
        if ($s['name'] -eq $sel) { $ui.LbServers.SelectedItem = $it }
    }
    if (-not $ui.LbServers.SelectedItem -and $ui.LbServers.Items.Count) {
        $first = $ui.LbServers.Items | Where-Object { $sv = $_.Tag; $st.Servers | Where-Object { $_['name'] -eq $sv -and -not (Test-RosTrue $_['disabled']) } } | Select-Object -First 1
        if (-not $first) { $first = $ui.LbServers.Items[0] }
        $ui.LbServers.SelectedItem = $first
    }

    # country from CA
    if (-not $ui.TbCountry.Text.Trim()) {
        $src = $st.Servers | Where-Object { $_['name'] -eq (Get-SelectedServerName) } | Select-Object -First 1
        if ($src) { $sc = Get-StateCert $st $src['certificate']; if ($sc) { $ca = Get-StateCert $st $sc['ca']; if ($ca -and $ca['country']) { $ui.TbCountry.Text = $ca['country'] } } }
    }
    if (-not $ui.TbPort.Text.Trim()) { try { $ui.TbPort.Text = [string](Get-OvpnSuggestedPort $st) } catch { } }
    Update-PortCheck
    Update-UsersList
    Update-SetupUi

    # maintenance grids
    $certs = foreach ($cc in @($st.Certificates | Where-Object { $_['key-usage'] -match 'tls-client' -and $_['ca'] })) {
        $s = if (Test-RosTrue $cc['revoked']) { 'відкликаний' } elseif (Test-RosTrue $cc['expired']) { 'прострочений' } else { 'діє' }
        $stt = if ($s -eq 'діє') { 'OK' } elseif ($s -eq 'прострочений') { 'WARN' } else { 'SKIP' }
        [pscustomobject]@{ Icon = (Get-Glyph $stt); Status = $stt; Name = $cc['name']; CN = $cc['common-name']; ValidTo = $cc['invalid-after']; Key = "$($cc['key-type']) $($cc['key-size'])"; State = $s }
    }
    $ui.DgCerts.ItemsSource = @($certs)
    $srvs = foreach ($s in $st.Servers) {
        $en = -not (Test-RosTrue $s['disabled'])
        $z = Test-ZeroTrustPort -State $st -Port ([int]$s['port']) -Protocol $s['protocol']
        [pscustomobject]@{ Icon = (Get-Glyph $(if ($en) { 'OK' } else { 'SKIP' })); Status = $(if ($en) { 'OK' } else { 'SKIP' }); Name = $s['name']; Port = $s['port']; Proto = $s['protocol']
            State = $(if ($en) { 'увімкнено' } else { 'вимкнено' }); InRule = $(if ($z.AllowRule) { "так ($($z.AllowRule['.id']))" } else { 'ні' }); Comment = $s['comment']
        }
    }
    $ui.DgServers.ItemsSource = @($srvs)
    $ui.DgSched.ItemsSource = @($st.Schedulers | ForEach-Object { [pscustomobject]@{ Name = $_['name']; When = "$($_['start-date']) $($_['start-time'])"; Comment = $_['comment'] } })
}

function Complete-RouterJob($out, $err, [switch]$SwitchToDiag) {
    if ($err) {
        $m = Get-InnerMessage $err
        if ($m -match 'not enough permissions') {
            $m += "`n`nAPI-користувачу бракує прав. Потрібні політики групи: api, read, write, test, ftp, sensitive.`n/user group add name=ovpn-admin policy=api,read,write,test,ftp,sensitive`n/user set $($ui.TbApiUser.Text.Trim()) group=ovpn-admin"
        }
        Show-Error $m; return $false
    }
    if ($out) {
        $script:State = $out['State']
        $script:Checks = @($out['Checks'])
        Show-Checks
        Show-State
        Save-Settings
        if ($SwitchToDiag) { $ui.Tabs.SelectedItem = $ui.TabDiag }
    }
    return $true
}

# ====================================================================== params / validation
function Update-ValidTo {
    $d = 0
    if ([int]::TryParse($ui.TbDays.Text.Trim(), [ref]$d) -and $d -gt 0) { $ui.TbValidTo.Text = "  діятиме до {0:yyyy-MM-dd}" -f (Get-Date).AddDays($d) }
    else { $ui.TbValidTo.Text = '' }
}

function Set-EoyDays {
    $y = Get-YearInt
    if ($y -ge 2000) {
        $days = [int]((New-Object DateTime $y, 12, 31) - (Get-Date).Date).TotalDays
        if ($days -lt 30) { $days = 30 }
        $ui.TbDays.Text = [string]$days
    }
}

function Update-YearFields {
    $y = $ui.TbYear.Text.Trim()
    if ($y -notmatch '^20\d\d$') { return }
    foreach ($pair in @(@('TbCertName', 'CertNameTpl'), @('TbCertCn', 'CertCnTpl'), @('TbFriendly', 'FriendlyTpl'), @('TbNewServer', 'NewServerTpl'))) {
        $tb = $ui[$pair[0]]; $tpl = $script:Settings[$pair[1]]
        $prevAuto = $script:AutoValues[$pair[0]]
        if (-not $tb.Text -or $tb.Text -eq $prevAuto) {
            $v = Expand-Tpl $tpl $y
            $tb.Text = $v
            $script:AutoValues[$pair[0]] = $v
        }
    }
    if (-not $ui.TbCutDate.Text -or $ui.TbCutDate.Text -eq $script:AutoValues['TbCutDate']) {
        $v = "$y-01-15"; $ui.TbCutDate.Text = $v; $script:AutoValues['TbCutDate'] = $v
    }
    if (-not $ui.TbDays.Text -or $ui.TbDays.Text -eq $script:AutoValues['TbDays']) { Set-EoyDays; $script:AutoValues['TbDays'] = $ui.TbDays.Text }
    $ui.TbOutDir.Text = "Тека: $(Get-OutDir)"
    Clear-Plan
}

function Update-PortCheck {
    $st = $script:State
    $p = 0
    if (-not $st -or -not [int]::TryParse($ui.TbPort.Text.Trim(), [ref]$p)) { $ui.TbPortCheck.Text = ''; return }
    $src = $st.Servers | Where-Object { $_['name'] -eq (Get-SelectedServerName) } | Select-Object -First 1
    if ($src -and [int]$src['port'] -eq $p) { $ui.TbPortCheck.Text = "Порт збігається з поточним — сервер і firewall не змінюються, лише нові сертифікати."; $ui.TbPortCheck.Foreground = $Window.FindResource('InfoBrush'); return }
    $ex = $st.Servers | Where-Object { $_['name'] -eq $ui.TbNewServer.Text.Trim() -and [int]$_['port'] -eq $p } | Select-Object -First 1
    $busy = if ($ex) { $null } else { Test-OvpnPortFree $st $p }
    $zt = Test-ZeroTrustPort -State $st -Port $p -Protocol $(if ($src) { $src['protocol'] } else { 'tcp' })
    $f = @($zt.Checks | Where-Object { $_.Status -eq 'FAIL' })
    if ($busy) { $ui.TbPortCheck.Text = "✖ $busy"; $ui.TbPortCheck.Foreground = $Window.FindResource('FailBrush') }
    elseif ($f.Count) { $ui.TbPortCheck.Text = "✖ $($f[0].Detail)"; $ui.TbPortCheck.Foreground = $Window.FindResource('FailBrush') }
    else {
        $rule = $null
        if ($src) { $rule = (Test-ZeroTrustPort -State $st -Port ([int]$src['port']) -Protocol $src['protocol']).AllowRule }
        $ui.TbPortCheck.Text = "✔ Порт вільний і закритий для невідомих адрес. Буде доданий у правило $(if ($rule) { $rule['.id'] } else { '?' }) (src-address-list=$($st.AllowList))."
        $ui.TbPortCheck.Foreground = $Window.FindResource('OkBrush')
    }
}

function Get-UiParams {
    $days = 0; [void][int]::TryParse($ui.TbDays.Text.Trim(), [ref]$days)
    $port = 0; [void][int]::TryParse($ui.TbPort.Text.Trim(), [ref]$port)
    return @{
        Year = (Get-YearInt); Days = $days; SourceServer = (Get-SelectedServerName); NewServerName = $ui.TbNewServer.Text.Trim(); Port = $port
        VpnHost = $ui.TbHost.Text.Trim(); VpnHost2 = $ui.TbHost2.Text.Trim(); Routes = @(Get-RoutesFromUi)
        CertName = $ui.TbCertName.Text.Trim(); CertCn = $ui.TbCertCn.Text.Trim(); Country = $ui.TbCountry.Text.Trim().ToUpper()
        KeySize = (Get-KeySize); Digest = (Get-Digest); KeyPass = $ui.PbKey1.Password; ArchivePass = $ui.PbArc1.Password
        FriendlyName = $ui.TbFriendly.Text.Trim(); PortalUrl = $ui.TbPortal.Text.Trim(); IncludeReadme = [bool]$ui.CbReadme.IsChecked; Modern = [bool]$ui.CbModern.IsChecked
        DeleteOpen = [bool]$ui.CbDeleteOpen.IsChecked; DoBackup = [bool]$ui.CbBackup.IsChecked; Schedule = [bool]$ui.CbSchedule.IsChecked
        CutDate = $ui.TbCutDate.Text.Trim(); CutTime = $ui.TbCutTime.Text.Trim()
        OutDir = (Get-OutDir); ToolsDir = (Join-Path $Root 'tools\7z'); AllowList = $script:Settings.AllowList
        AuthMode = (Get-AuthMode); Users = @(Get-UiUsers); UserProfile = $ui.TbUserProfile.Text.Trim(); UserCertTpl = $ui.TbUserCertTpl.Text.Trim()
        SaveCredentials = [bool]$ui.CbSaveCreds.IsChecked
    }
}

function Get-UiErrors {
    $e = New-Object System.Collections.Generic.List[string]
    if (-not $script:State) { $e.Add('Спочатку підключіться до роутера (вкладка «Підключення»).'); return $e.ToArray() }
    if ($ui.PbKey1.Password -ne $ui.PbKey2.Password) { $e.Add('Паскей ключа і підтвердження не збігаються') }
    if ($ui.PbArc1.Password -ne $ui.PbArc2.Password) { $e.Add('Пароль архіву і підтвердження не збігаються') }
    $P = Get-UiParams
    foreach ($x in (Test-OvpnParams -State $script:State -P $P)) { $e.Add($x) }
    $crit = @($script:Checks | Where-Object { $_.Status -eq 'FAIL' -and $_.Critical -and $_.Group -notlike 'Клієнтські*' })
    foreach ($c in $crit) { $e.Add("Діагностика: $($c.Group) / $($c.Name): $($c.Detail)") }
    return $e.ToArray()
}

function Clear-Plan {
    if ($null -ne $script:LastPlanHash) {
        $script:LastPlanHash = $null
        $ui.BtnRun.IsEnabled = $false
        $ui.TbPlan.Text = 'Параметри змінено — натисніть «Переглянути зміни» ще раз.'
    }
}

function Get-ParamsHash($P) {
    $copy = @{}; foreach ($k in $P.Keys) { if ($k -notin @('KeyPass', 'ArchivePass', 'Users', 'RadiusSecret', 'CaBackupPass')) { $copy[$k] = $P[$k] } }
    if ($P.ContainsKey('Users')) { $copy['Users'] = (@($P.Users) | ForEach-Object { "$($_.Name)/$($_.IsNew)/$("$($_.Password)".GetHashCode())" }) -join ';' }
    foreach ($k in @('RadiusSecret', 'CaBackupPass')) { if ($P.ContainsKey($k)) { $copy[$k] = "$($P[$k])".GetHashCode() } }
    if (-not $P.ContainsKey('KeyPass')) { return (($copy.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value -join ',')" }) -join '|') }
    $copy['kp'] = $P.KeyPass.GetHashCode(); $copy['ap'] = $P.ArchivePass.GetHashCode()
    return (($copy.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value -join ',')" }) -join '|')
}

# ====================================================================== users / setup helpers
function Get-AuthMode { if ($ui.RbModeLocal.IsChecked) { return 'local' } return 'radius' }

function Update-ModeUi {
    $local = (Get-AuthMode) -eq 'local'
    $ui.GrLocal.IsEnabled = $local
    $ui.GrLocal.Opacity = $(if ($local) { 1 } else { 0.45 })
    $ui.TbCertName.IsEnabled = -not $local
    $ui.TbCertCn.IsEnabled = -not $local
    $ui.TbModeHint.Text = if ($local) {
        "Для кожного користувача: /ppp secret (service=ovpn) + окремий сертифікат CN=логін + окремі архіви. RouterOS не прив'язує сертифікат до логіна: доступ дає будь-який дійсний сертифікат нашого CA + правильний пароль. Щоб забрати доступ людини — вимкніть її secret і відкличте її сертифікат."
    } else {
        "Логін і пароль перевіряє RADIUS-сервер (/radius). Усі отримують однаковий сертифікат (CN з «Параметри року»). Користувачі на роутері не створюються."
    }
}

function Get-UiUsers {
    $list = @()
    foreach ($it in $ui.LbUsers.Items) { if ($it.IsChecked) { $list += @{ Name = [string]$it.Tag; Password = ''; IsNew = $false } } }
    foreach ($line in ($ui.TbNewUsers.Text -split "`r?`n")) {
        $l = $line.Trim()
        if (-not $l) { continue }
        $parts = $l.Split(';', 2)
        $list += @{ Name = $parts[0].Trim(); Password = $(if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }); IsNew = $true }
    }
    return $list
}

function Update-UsersList {
    $st = $script:State
    $checked = @($ui.LbUsers.Items | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag })
    $ui.LbUsers.Items.Clear()
    foreach ($u in @($st.Secrets | Where-Object { $_['service'] -in @('ovpn', 'any') } | Sort-Object { $_['name'] })) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Tag = $u['name']
        $cb.Content = "{0}   ·  {1}  ·  {2}{3}" -f $u['name'], $u['service'], $u['profile'], $(if (Test-RosTrue $u['disabled']) { '  ·  вимкнено' } else { '' })
        $cb.IsChecked = ($checked -contains $u['name'])
        $cb.Add_Click({ Clear-Plan })
        [void]$ui.LbUsers.Items.Add($cb)
    }
    if (-not $ui.TbUserProfile.Text.Trim()) {
        $src = $st.Servers | Where-Object { $_['name'] -eq (Get-SelectedServerName) } | Select-Object -First 1
        if ($src) { $ui.TbUserProfile.Text = $src['default-profile'] }
    }
}

function Get-SetupKey([string]$Prefix) {
    if ($ui["Rb${Prefix}Ec"].IsChecked) { return 'secp384r1' }
    if ($ui["Rb${Prefix}8192"].IsChecked) { return '8192' }
    return '4096'
}

function Get-UiSetup {
    $port = 0; [void][int]::TryParse($ui.TbSrvPort.Text.Trim(), [ref]$port)
    $cd = 0; [void][int]::TryParse($ui.TbCaDays.Text.Trim(), [ref]$cd)
    $sd = 0; [void][int]::TryParse($ui.TbSrvDays.Text.Trim(), [ref]$sd)
    $country = $ui.TbCountry.Text.Trim().ToUpper(); if (-not $country) { $country = 'UA' }
    return @{
        CaName = $ui.TbCaName.Text.Trim(); CaCn = $ui.TbCaCn.Text.Trim(); CaKeySize = (Get-SetupKey 'Ca'); CaDays = $cd; Country = $country
        SrvCertName = $ui.TbSrvCertName.Text.Trim(); SrvCn = $ui.TbSrvCn.Text.Trim(); SrvKeySize = (Get-SetupKey 'Srv'); SrvDays = $sd
        PoolName = $ui.TbPoolName.Text.Trim(); PoolRange = $ui.TbPoolRange.Text.Trim(); ProfileName = $ui.TbProfName.Text.Trim()
        LocalAddress = $ui.TbLocalAddr.Text.Trim(); DnsServer = $ui.TbDns.Text.Trim(); ServerName = $ui.TbSrvName.Text.Trim(); Port = $port
        Protocol = $(if ($ui.RbProtoUdp.IsChecked) { 'udp' } else { 'tcp' }); Cipher = 'aes256-gcm'; Auth = 'sha256'
        UserAuth = $(if ($ui.RbUaMs.IsChecked) { 'mschap2' } else { 'pap' })
        AddFirewall = [bool]$ui.CbSetupFw.IsChecked; AllowList = $script:Settings.AllowList
        RadiusEnable = [bool]$ui.CbSetupRadius.IsChecked; RadiusAddress = $ui.TbRadAddr.Text.Trim(); RadiusSecret = $ui.PbRadSecret.Password
        CaBackupPass = $ui.PbCaBackup.Password; OutDir = (Join-Path $Root 'out\ca-backup')
    }
}

$script:SetupPlanHash = $null
function Clear-SetupPlan {
    if ($null -ne $script:SetupPlanHash) {
        $script:SetupPlanHash = $null; $ui.BtnSetupRun.IsEnabled = $false
        $ui.TbSetupPlan.Text = 'Параметри змінено — натисніть «Переглянути зміни» ще раз.'
    }
}

function Update-SetupUi {
    $st = $script:State
    if (-not $st) { return }
    $d = Get-OvpnSetupDefaults $st
    $map = @{ TbCaName = 'CaName'; TbCaCn = 'CaCn'; TbSrvCertName = 'SrvCertName'; TbSrvCn = 'SrvCn'; TbPoolName = 'PoolName'; TbPoolRange = 'PoolRange'
        TbProfName = 'ProfileName'; TbLocalAddr = 'LocalAddress'; TbSrvName = 'ServerName'; TbSrvPort = 'Port' }
    foreach ($k in $map.Keys) { if (-not $ui[$k].Text.Trim()) { $ui[$k].Text = [string]$d[$map[$k]] } }
    if ($d.Protocol -eq 'udp') { $ui.RbProtoUdp.IsChecked = $true }
    $S = Get-UiSetup
    $mark = { param($ok, $text) if ($ok) { "$([char]0x2714) $text" } else { "$([char]0x25CB) $text — буде створено" } }
    $ca = Get-StateCert $st $S.CaName
    $sc = Get-StateCert $st $S.SrvCertName
    $srv = $st.Servers | Where-Object { $_['name'] -eq $S.ServerName } | Select-Object -First 1
    $zt = $null; if ($srv) { $zt = Test-ZeroTrustPort -State $st -Port ([int]$srv['port']) -Protocol $srv['protocol'] }
    $lines = @(
        (& $mark $ca "CA $($S.CaName)"),
        (& $mark $sc "Серверний сертифікат $($S.SrvCertName)"),
        (& $mark ($st.Pools | Where-Object { $_['name'] -eq $S.PoolName }) "Пул $($S.PoolName)"),
        (& $mark ($st.Profiles | Where-Object { $_['name'] -eq $S.ProfileName }) "PPP-профіль $($S.ProfileName)"),
        (& $mark $srv "OpenVPN-сервер $($S.ServerName)$(if ($srv) { " ($($srv['protocol'])/$($srv['port']))" })"),
        $(if ($zt -and $zt.AllowRule) { "$([char]0x2714) Firewall: порт через $($st.AllowList) ($($zt.AllowRule['.id']))" } else { "$([char]0x25CB) Firewall: порт через $($st.AllowList) — буде додано" }),
        $(if (Test-RosTrue (Get-RosVal $st.Aaa 'use-radius')) { "$([char]0x2714) RADIUS для PPP увімкнено" } else { "$([char]0x25CB) RADIUS вимкнено (опційно)" })
    )
    $all = [bool]($ca -and $sc -and $srv)
    $ui.TbSetupStatus.Text = ($lines -join "`n")
    Set-SetupMode -Configured $all
    if ($ca) {
        $ui.TbCaStatus.Text = "Знайдено: $($ca['name']) · CN=$($ca['common-name']) · $($ca['key-type']) $($ca['key-size']) · до $($ca['invalid-after']) · trusted=$($ca['trusted']) · приватний ключ: $(if (Test-RosTrue $ca['private-key']) { 'є' } else { 'НЕМАЄ' })"
        $ui.TbCaStatus.Foreground = $Window.FindResource($(if ((Test-RosTrue $ca['trusted']) -and (Test-RosTrue $ca['private-key'])) { 'OkBrush' } else { 'WarnBrush' }))
    } else {
        $ui.TbCaStatus.Text = "CA '$($S.CaName)' не знайдено — буде створено самопідписаний CA."
        $ui.TbCaStatus.Foreground = $Window.FindResource('WarnBrush')
    }
    $ui.BtnCaTrust.IsEnabled = [bool]($ca -and -not (Test-RosTrue $ca['trusted']))
    $ui.BtnCaBackup.IsEnabled = [bool]$ca
}

$script:SetupExpanded = $null   # $null = авто (згорнуто, якщо вже налаштовано)
$script:SetupConfigured = $false

function Set-SetupHeader([bool]$Optional) {
    $sp = New-Object System.Windows.Controls.StackPanel
    $t = New-Object System.Windows.Controls.TextBlock
    $t.Text = 'CA і сервер'
    [void]$sp.Children.Add($t)
    if ($Optional) {
        $h = New-Object System.Windows.Controls.TextBlock
        $h.Text = "необов'язково — вже налаштовано"
        $h.FontSize = 11
        $h.Foreground = $Window.FindResource('OkBrush')
        [void]$sp.Children.Add($h)
    }
    $ui.TabSetup.Header = $sp
}

function Set-SetupMode([bool]$Configured) {
    $script:SetupConfigured = $Configured
    Set-SetupHeader $Configured
    $ui.BdSetupBanner.Visibility = 'Visible'
    if ($Configured) {
        $ui.BdSetupBanner.Background = New-Object Windows.Media.SolidColorBrush ([Windows.Media.Color]::FromRgb(0x13, 0x2B, 0x22))
        $ui.BdSetupBanner.BorderBrush = $Window.FindResource('OkBrush')
        $ui.TbSetupBannerIcon.Text = [string][char]0x2714
        $ui.TbSetupBannerIcon.Foreground = $Window.FindResource('OkBrush')
        $ui.TbSetupBannerTitle.Text = "OpenVPN уже налаштовано — цю вкладку можна пропустити"
        $ui.TbSetupBannerText.Text = "Для щорічного оновлення перейдіть до «Параметри року» → «Користувачі» → «Виконання». Тут рекомендовано лише один раз зробити «Зберегти backup CA» (блок «Кореневий CA» нижче). Первинне налаштування потрібне тільки для роутера, де OpenVPN ще не було."
    } else {
        $ui.BdSetupBanner.Background = New-Object Windows.Media.SolidColorBrush ([Windows.Media.Color]::FromRgb(0x33, 0x29, 0x14))
        $ui.BdSetupBanner.BorderBrush = $Window.FindResource('WarnBrush')
        $ui.TbSetupBannerIcon.Text = [string][char]0x26A0
        $ui.TbSetupBannerIcon.Foreground = $Window.FindResource('WarnBrush')
        $ui.TbSetupBannerTitle.Text = 'OpenVPN на роутері ще не налаштовано — почніть з цієї вкладки'
        $ui.TbSetupBannerText.Text = "Перевірте параметри нижче, натисніть «Переглянути зміни» і «Виконати». Об'єкти, які вже є (позначені ✔), буде пропущено. Після цього — «Параметри року»."
    }
    $expanded = if ($null -ne $script:SetupExpanded) { $script:SetupExpanded } else { -not $Configured }
    $vis = if ($expanded) { 'Visible' } else { 'Collapsed' }
    foreach ($n in @('BdSetupSrvCert', 'SpSetupRight', 'BdSetupRun')) { $ui[$n].Visibility = $vis }
    $ui.BtnSetupToggle.Content = if ($expanded) { 'Згорнути первинне налаштування' } else { 'Показати первинне налаштування' }
    $ui.BtnSetupToggle.Visibility = if ($Configured) { 'Visible' } else { 'Collapsed' }
}

function Show-PermissionPopup {
    if (-not $script:State) { return }
    $perm = Get-OvpnPermissionReport $script:State
    if ($perm.Ok) { Write-OvpnLog -Level OK "Права API: усі потрібні політики є ($($perm.Have -join ','))"; return }
    Write-OvpnLog -Level WARN "Права API: бракує $($perm.Missing -join ', ')"
    if ($SmokeTest) { $script:SmokePerm = $perm; return }
    $txt = "Користувач '$($perm.User)', група '$($perm.Group)'.`r`nНаявні політики: $($perm.Have -join ', ')`r`n`r`nБракує:`r`n" +
        (($perm.Details | ForEach-Object { "  • $_" }) -join "`r`n") +
        "`r`n`r`nДіагностика працює, але збірка, первинне налаштування та експорт сертифікатів без цих прав неможливі.`r`n`r`nВиконайте на MikroTik (New Terminal):`r`n`r`n" + ($perm.Fix -join "`r`n") +
        "`r`n`r`nПісля цього перепідключіться."
    if (Show-Confirm 'Недостатньо прав API' $txt 'Скопіювати команди') {
        [System.Windows.Clipboard]::SetText((($perm.Fix | Where-Object { $_ -notlike '#*' }) | Select-Object -First 2) -join "`r`n")
        Write-OvpnLog -Level OK 'Команди скопійовано в буфер обміну'
    }
}

# ====================================================================== init values
$script:Settings = Read-Settings
$ui.TbRouter.Text = $script:Settings.Router
$ui.TbApiPort.Text = [string]$script:Settings.ApiPort
$ui.TbApiUser.Text = $script:Settings.ApiUser
$ui.TbHost.Text = $script:Settings.VpnHost
$ui.TbHost2.Text = $script:Settings.VpnHost2
$ui.TbRoutes.Text = (@($script:Settings.Routes) -join "`r`n")
$ui.TbPortal.Text = $script:Settings.PortalUrl
$ui.TbCountry.Text = $script:Settings.Country
$ui.CbModern.IsChecked = [bool]$script:Settings.Modern
$ui.CbDeleteOpen.IsChecked = [bool]$script:Settings.DeleteOpen
$ui.CbBackup.IsChecked = [bool]$script:Settings.Backup
$ui.CbSchedule.IsChecked = [bool]$script:Settings.Schedule
$ui.CbReadme.IsChecked = [bool]$script:Settings.IncludeReadme
$ui.TbPortal.IsEnabled = [bool]$ui.CbReadme.IsChecked
if ($script:Settings.AuthMode -eq 'local') { $ui.RbModeLocal.IsChecked = $true } else { $ui.RbModeRadius.IsChecked = $true }
$ui.TbUserCertTpl.Text = $script:Settings.UserCertTpl
$ui.TbUserProfile.Text = $script:Settings.UserProfile
$ui.CbSaveCreds.IsChecked = [bool]$script:Settings.SaveCredentials
switch ($script:Settings.KeySize) { '4096' { $ui.RbK4096.IsChecked = $true } '8192' { $ui.RbK8192.IsChecked = $true } 'secp384r1' { $ui.RbKec.IsChecked = $true } default { $ui.RbK16384.IsChecked = $true } }
if ($script:Settings.Digest -eq 'sha256') { $ui.RbD256.IsChecked = $true } else { $ui.RbD512.IsChecked = $true }
$now = Get-Date
$ui.TbYear.Text = [string]$(if ($now.Month -ge 9) { $now.Year + 1 } else { $now.Year })
Update-YearFields
Update-ValidTo

function Update-KeyHint {
    $k = Get-KeySize
    $ui.TbKeyHint.Text = switch ($k) {
        '16384' { 'RSA 16384: підпис на роутері може тривати 5–20 хв, handshake клієнтів повільніший. Так було у 2026.' }
        '8192' { 'RSA 8192: як у CA та серверного сертифіката. Підпис ~1–3 хв.' }
        '4096' { 'RSA 4096: сучасний стандарт, швидкий підпис і handshake.' }
        'secp384r1' { 'EC P-384: дуже швидко, сучасно; потрібні клієнти OpenVPN 2.4+ (перевірте на тестовому ПК).' }
    }
}
Update-KeyHint

# ====================================================================== events
$ui.BtnConnect.Add_Click({
        Save-Settings
        Write-OvpnLog "Підключення до $($ui.TbRouter.Text)…"
        Start-RouterJob -Title 'Діагностика' -OnDone { param($o, $e) if (Complete-RouterJob $o $e -SwitchToDiag) { Show-PermissionPopup } }
    })
$ui.BtnDiagRefresh.Add_Click({ Start-RouterJob -Title 'Діагностика' -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) } })
$ui.CbOnlyProblems.Add_Click({ Show-Checks })
$ui.BtnDiagCopy.Add_Click({
        $t = ($script:Checks | ForEach-Object { "[{0}] {1} / {2}: {3}{4}" -f $_.Status, $_.Group, $_.Name, $_.Detail, $(if ($_.Fix) { "  → $($_.Fix)" } else { '' }) }) -join "`r`n"
        if ($t) { [System.Windows.Clipboard]::SetText($t); Write-OvpnLog -Level OK 'Звіт діагностики скопійовано в буфер обміну' }
    })

$ui.TbYear.Add_TextChanged({ Update-YearFields; Update-ValidTo })
$ui.TbDays.Add_TextChanged({ Update-ValidTo; Clear-Plan })
$ui.BtnDaysEoy.Add_Click({ Set-EoyDays })
$ui.TbPort.Add_TextChanged({ Update-PortCheck; Clear-Plan })
$ui.TbNewServer.Add_TextChanged({ Update-PortCheck; Clear-Plan })
$ui.LbServers.Add_SelectionChanged({ Update-PortCheck; Clear-Plan })
foreach ($n in @('TbHost', 'TbHost2', 'TbRoutes', 'TbCertName', 'TbCertCn', 'TbCountry', 'TbFriendly', 'TbPortal', 'TbCutDate', 'TbCutTime')) { $ui[$n].Add_TextChanged({ Clear-Plan }) }
foreach ($n in @('RbK4096', 'RbK8192', 'RbK16384', 'RbKec', 'RbD256', 'RbD512', 'CbModern', 'CbDeleteOpen', 'CbBackup', 'CbSchedule', 'CbReadme')) { $ui[$n].Add_Click({ Update-KeyHint; Clear-Plan }) }
$ui.CbReadme.Add_Click({ $ui.TbPortal.IsEnabled = [bool]$ui.CbReadme.IsChecked })
foreach ($n in @('PbKey1', 'PbKey2', 'PbArc1', 'PbArc2')) { $ui[$n].Add_PasswordChanged({ Clear-Plan }) }

$ui.BtnSuggestPort.Add_Click({
        if (-not $script:State) { Show-Error 'Спочатку підключіться до роутера.'; return }
        $ui.TbPort.Text = [string](Get-OvpnSuggestedPort $script:State)
    })
$ui.BtnCheckHost.Add_Click({
        $res = @()
        $st = $script:State
        if (-not $st) { $st = @{ WanIps = @(); DnsStatic = @() } }
        $res += Test-OvpnHost $st $ui.TbHost.Text.Trim() 'VPN-хост'
        if ($ui.TbHost2.Text.Trim()) { $res += Test-OvpnHost $st $ui.TbHost2.Text.Trim() 'Резервний хост' }
        $ui.TbHostCheck.Text = ($res | ForEach-Object { "$($_.Icon) $($_.Name): $($_.Detail)" }) -join "`n"
    })
$ui.BtnGenKey.Add_Click({
        $s = New-Secret 20
        $ui.PbKey1.Password = $s; $ui.PbKey2.Password = $s
        $ui.TbKeyShow.Text = "Паскей: $s"; $ui.TbKeyShow.Visibility = 'Visible'
    })
$ui.BtnGenArc.Add_Click({
        $s = New-Secret 20
        $ui.PbArc1.Password = $s; $ui.PbArc2.Password = $s
        $ui.TbArcShow.Text = "Пароль архіву: $s"; $ui.TbArcShow.Visibility = 'Visible'
    })

$ui.BtnPreview.Add_Click({
        $errs = Get-UiErrors
        if ($errs.Count) {
            $ui.TbPlan.Text = "Виправте перед виконанням:`r`n`r`n - " + ($errs -join "`r`n - ")
            $script:LastPlanHash = $null; $ui.BtnRun.IsEnabled = $false
            $ui.Tabs.SelectedItem = $ui.TabRun
            return
        }
        $P = Get-UiParams
        $plan = Get-OvpnBuildPlan -State $script:State -P $P
        $ui.TbPlan.Text = ($plan -join "`r`n")
        $script:LastPlanHash = Get-ParamsHash $P
        $ui.BtnRun.IsEnabled = $true
        $ui.Tabs.SelectedItem = $ui.TabRun
        Save-Settings
    })

$ui.BtnRun.Add_Click({
        $P = Get-UiParams
        if ((Get-ParamsHash $P) -ne $script:LastPlanHash) { Clear-Plan; return }
        $plan = Get-OvpnBuildPlan -State $script:State -P $P
        if (-not (Show-Confirm "Застосувати зміни для $($P.Year)?" (($plan -join "`r`n") + "`r`n`r`nАктивні сесії старого сервера не обриваються.") 'Виконати')) { return }
        Reset-Steps
        New-Item -ItemType Directory -Force -Path $P.OutDir | Out-Null
        Write-OvpnLog -Level STEP "=== Старт збірки $($P.Year) ==="
        $script:LastBuildP = $P
        Start-RouterJob -Title "Збірка $($P.Year)" -Op '$opResult = Invoke-OvpnBuild -Connection $c -P $A.P' -Extra @{ P = $P } -OnDone {
            param($o, $e)
            if ($e) {
                foreach ($s in @($script:Steps)) { if ($s.Status -eq 'RUN') { Update-Step ([pscustomobject]@{ Key = $s.Key; Status = 'fail'; Detail = (Get-InnerMessage $e) }) } }
                Show-Error ("Збірку зупинено:`n`n" + (Get-InnerMessage $e) + "`n`nДеталі — у журналі. Повторний запуск продовжить з наявного сертифіката/сервера.")
                return
            }
            [void](Complete-RouterJob $o $null)
            $script:LastPlanHash = $null; $ui.BtnRun.IsEnabled = $false
            $files = @($o['OpResult']['Files'])
            $creds = @($o['OpResult']['Credentials'] | Where-Object { $_.New })
            Write-OvpnLog -Level OK "=== Готово: $($files.Count) файлів у $(Get-OutDir) ==="
            $txt = "Створено:`r`n" + (($files | ForEach-Object { '  ' + $_ }) -join "`r`n") + "`r`n`r`nSHA256 сертифіката: $($o['OpResult']['Fingerprint'])"
            $credText = ''
            if ($creds.Count) {
                $credText = (@('login;password') + @($creds | ForEach-Object { "$($_.User);$($_.Password)" })) -join "`r`n"
                $txt += "`r`n`r`nНОВІ КОРИСТУВАЧІ (паролі ніде не збережено$(if ($script:LastBuildP.SaveCredentials) { ', крім credentials.csv' })):`r`n" + $credText
            }
            $ok = if ($creds.Count) { 'Скопіювати облікові дані й відкрити теку' } else { 'Відкрити теку' }
            if (Show-Confirm 'Готово' $txt $ok) {
                if ($credText) { [System.Windows.Clipboard]::SetText($credText); Write-OvpnLog -Level OK 'Облікові дані нових користувачів скопійовано в буфер обміну' }
                Start-Process explorer.exe (Get-OutDir)
            }
        }
    })

$ui.BtnOpenOut.Add_Click({ $d = Get-OutDir; if (-not (Test-Path $d)) { $d = Join-Path $Root 'out' }; New-Item -ItemType Directory -Force -Path $d | Out-Null; Start-Process explorer.exe $d })
$ui.BtnLogClear.Add_Click({ $ui.TbLog.Clear() })
$ui.BtnLogOpen.Add_Click({ if (Test-Path $script:LogFile) { Start-Process notepad.exe $script:LogFile } })

# --- users tab
foreach ($n in @('RbModeRadius', 'RbModeLocal')) { $ui[$n].Add_Click({ Update-ModeUi; Clear-Plan }) }
foreach ($n in @('TbNewUsers', 'TbUserProfile', 'TbUserCertTpl')) { $ui[$n].Add_TextChanged({ Clear-Plan }) }
$ui.CbSaveCreds.Add_Click({ Clear-Plan })
$ui.BtnUsersAll.Add_Click({ foreach ($it in $ui.LbUsers.Items) { $it.IsChecked = $true }; Clear-Plan })
$ui.BtnUsersNone.Add_Click({ foreach ($it in $ui.LbUsers.Items) { $it.IsChecked = $false }; Clear-Plan })
Update-ModeUi

# --- CA & initial setup tab
foreach ($n in @('TbCaName', 'TbCaCn', 'TbCaDays', 'TbSrvCertName', 'TbSrvCn', 'TbSrvDays', 'TbPoolName', 'TbPoolRange', 'TbProfName', 'TbLocalAddr', 'TbDns', 'TbSrvName', 'TbSrvPort', 'TbRadAddr')) {
    $ui[$n].Add_TextChanged({ Clear-SetupPlan })
}
foreach ($n in @('RbCa4096', 'RbCa8192', 'RbCaEc', 'RbSrv4096', 'RbSrv8192', 'RbSrvEc', 'RbProtoTcp', 'RbProtoUdp', 'RbUaPap', 'RbUaMs', 'CbSetupFw', 'CbSetupRadius')) { $ui[$n].Add_Click({ Clear-SetupPlan }) }
foreach ($n in @('PbRadSecret', 'PbCaBackup')) { $ui[$n].Add_PasswordChanged({ Clear-SetupPlan }) }
$ui.BtnSetupToggle.Add_Click({
        $cur = $ui.BdSetupRun.Visibility -eq 'Visible'
        $script:SetupExpanded = -not $cur
        Set-SetupMode -Configured $script:SetupConfigured
    })
$ui.BtnSetupPort.Add_Click({
        if (-not $script:State) { Show-Error 'Спочатку підключіться до роутера.'; return }
        $ui.TbSrvPort.Text = [string](Get-OvpnSuggestedPort $script:State)
    })
$ui.BtnSetupPreview.Add_Click({
        if (-not $script:State) { Show-Error 'Спочатку підключіться до роутера.'; return }
        $S = Get-UiSetup
        $errs = @(Test-OvpnSetupParams -State $script:State -S $S)
        $perm = Get-OvpnPermissionReport $script:State
        if (-not $perm.Ok) { $errs += "Права API: бракує $($perm.Missing -join ', ')" }
        if ($errs.Count) {
            $ui.TbSetupPlan.Text = "Виправте перед виконанням:`r`n`r`n - " + ($errs -join "`r`n - ")
            $script:SetupPlanHash = $null; $ui.BtnSetupRun.IsEnabled = $false; return
        }
        $ui.TbSetupPlan.Text = ((Get-OvpnSetupPlan -State $script:State -S $S) -join "`r`n")
        $script:SetupPlanHash = Get-ParamsHash $S
        $ui.BtnSetupRun.IsEnabled = $true
    })
$ui.BtnSetupRun.Add_Click({
        $S = Get-UiSetup
        if ((Get-ParamsHash $S) -ne $script:SetupPlanHash) { Clear-SetupPlan; return }
        $plan = Get-OvpnSetupPlan -State $script:State -S $S
        if (-not (Show-Confirm 'Первинне налаштування OpenVPN?' ($plan -join "`r`n") 'Виконати')) { return }
        Reset-SetupSteps
        Write-OvpnLog -Level STEP '=== Первинне налаштування ==='
        Start-RouterJob -Title 'Первинне налаштування' -Op '$opResult = Invoke-OvpnSetup -Connection $c -S $A.S' -Extra @{ S = $S } -OnDone {
            param($o, $e)
            if ($e) {
                foreach ($s in @($script:SetupSteps)) { if ($s.Status -eq 'RUN') { Update-Step ([pscustomobject]@{ Key = $s.Key; Status = 'fail'; Detail = (Get-InnerMessage $e) }) } }
                [void](Complete-RouterJob $null $e); return
            }
            [void](Complete-RouterJob $o $null)
            $script:SetupPlanHash = $null; $ui.BtnSetupRun.IsEnabled = $false
            $f = @($o['OpResult']['Files'])
            Show-Info ("Первинне налаштування завершено." + $(if ($f.Count) { "`n`nBackup CA:`n" + ($f -join "`n") } else { '' }) + "`n`nДалі: «Параметри року» → профілі.")
        }
    })
$ui.BtnCaTrust.Add_Click({
        $n = $ui.TbCaName.Text.Trim()
        if (-not (Show-Confirm 'Позначити CA trusted?' "/certificate set $n trusted=yes" 'Позначити')) { return }
        Start-RouterJob -Title 'CA trusted' -Op 'Set-RosCertTrusted -Connection $c -Name $A.Name' -Extra @{ Name = $n } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnCaBackup.Add_Click({
        $n = $ui.TbCaName.Text.Trim()
        $pp = $ui.PbCaBackup.Password
        if ($pp.Length -lt 8 -or $pp -match '["\s]') { Show-Error 'Паскей backup CA: мінімум 8 символів, без пробілів і лапок.'; return }
        $out = Join-Path $Root 'out\ca-backup'
        if (-not (Show-Confirm 'Зберегти backup CA?' "Експорт $n (сертифікат + приватний ключ, зашифрований паскеєм) у`r`n$out`r`n`r`nЗберігайте ці файли офлайн: з ними можна випускати довірені сертифікати." 'Зберегти')) { return }
        Start-RouterJob -Title 'Backup CA' -Op '$opResult = Export-OvpnCaBackup -Connection $c -CaName $A.Name -Passphrase $A.BPass -OutDir $A.Out' -Extra @{ Name = $n; BPass = $pp; Out = $out } -OnDone {
            param($o, $e)
            if (Complete-RouterJob $o $e) { Show-Info ("Backup CA збережено:`n" + (@($o['OpResult']) -join "`n")); Start-Process explorer.exe (Join-Path $Root 'out\ca-backup') }
        }
    })

# --- maintenance
$ui.BtnCertRevoke.Add_Click({
        $it = $ui.DgCerts.SelectedItem
        if (-not $it) { Show-Error 'Оберіть сертифікат'; return }
        if ($it.State -eq 'відкликаний') { Show-Info 'Сертифікат уже відкликаний'; return }
        $warn = if ($it.State -eq 'діє') { "`r`n`r`nУВАГА: сертифікат ДІЄ. Усі користувачі з профілем на ньому втратять доступ." } else { '' }
        if (-not (Show-Confirm 'Відкликати сертифікат?' "/certificate issued-revoke $($it.Name)  (CN=$($it.CN), до $($it.ValidTo))$warn" 'Відкликати' -Danger)) { return }
        Start-RouterJob -Title 'Відкликання' -Op 'Invoke-RosCertRevoke -Connection $c -Name $A.Name' -Extra @{ Name = $it.Name } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnCertRemove.Add_Click({
        $it = $ui.DgCerts.SelectedItem
        if (-not $it) { Show-Error 'Оберіть сертифікат'; return }
        if ($it.State -eq 'діє') { Show-Error 'Діючий сертифікат видаляти не можна — спочатку відкличте його або дочекайтесь закінчення терміну.'; return }
        if (-not (Show-Confirm 'Видалити сертифікат?' "/certificate remove $($it.Name)  (CN=$($it.CN), $($it.State))" 'Видалити' -Danger)) { return }
        Start-RouterJob -Title 'Видалення сертифіката' -Op 'Remove-RosCert -Connection $c -Name $A.Name' -Extra @{ Name = $it.Name } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnSrvEnable.Add_Click({
        $it = $ui.DgServers.SelectedItem
        if (-not $it) { Show-Error 'Оберіть сервер'; return }
        if (-not (Show-Confirm 'Увімкнути сервер?' "/interface ovpn-server server enable $($it.Name)  (порт $($it.Port))`r`nДоступ ззовні — лише якщо порт є в правилі MGMT_Allow ($($it.InRule))." 'Увімкнути')) { return }
        Start-RouterJob -Title 'Увімкнення сервера' -Op 'Set-OvpnServerEnabled -Connection $c -Name $A.Name -Enabled $true' -Extra @{ Name = $it.Name } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnSrvDisable.Add_Click({
        $it = $ui.DgServers.SelectedItem
        if (-not $it) { Show-Error 'Оберіть сервер'; return }
        $sess = @($script:State.Sessions).Count
        if (-not (Show-Confirm 'Вимкнути сервер?' "/interface ovpn-server server disable $($it.Name)  (порт $($it.Port))`r`n`r`nАктивні OVPN-сесії на роутері: $sess — сесії цього сервера буде розірвано." 'Вимкнути' -Danger)) { return }
        Start-RouterJob -Title 'Вимкнення сервера' -Op 'Set-OvpnServerEnabled -Connection $c -Name $A.Name -Enabled $false' -Extra @{ Name = $it.Name } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnSrvRemovePort.Add_Click({
        $it = $ui.DgServers.SelectedItem
        if (-not $it) { Show-Error 'Оберіть сервер'; return }
        $extra = if ($it.State -eq 'увімкнено') { "`r`n`r`nУВАГА: сервер увімкнений — після цього до нього не зможуть підключитися ззовні." } else { '' }
        if (-not (Show-Confirm 'Прибрати порт з правила?' "Порт $($it.Port) буде прибрано з dst-port allow-правила $($script:State.AllowList) ($($it.InRule)).$extra" 'Прибрати' -Danger)) { return }
        Start-RouterJob -Title 'Firewall' -Op '$st0 = Get-RouterState -Connection $c -AllowList $A.AllowList; $opResult = Remove-OvpnPortFromAllowRule -Connection $c -State $st0 -Port $A.Port -Protocol $A.Proto; Write-OvpnLog -Level OK $opResult' `
            -Extra @{ Port = [int]$it.Port; Proto = $it.Proto } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })
$ui.BtnSchedRemove.Add_Click({
        $it = $ui.DgSched.SelectedItem
        if (-not $it) { Show-Error 'Оберіть scheduler'; return }
        if (-not (Show-Confirm 'Скасувати перехід?' "/system scheduler remove $($it.Name)  ($($it.When))" 'Скасувати перехід' -Danger)) { return }
        Start-RouterJob -Title 'Scheduler' -Op 'Remove-OvpnScheduler -Connection $c -Name $A.Name' -Extra @{ Name = $it.Name } -OnDone { param($o, $e) [void](Complete-RouterJob $o $e) }
    })

$Window.Add_Closing({
        param($sender, $ev)
        if ($script:Busy) {
            $r = [System.Windows.MessageBox]::Show($Window, 'Операція ще виконується. Закрити програму? (операція на роутері може залишитись незавершеною)', 'OvpnBase', 'YesNo', 'Warning')
            if ($r -ne 'Yes') { $ev.Cancel = $true; return }
        }
        try { Save-Settings } catch { }
        $script:Timer.Stop()
    })


# Self-test: auto-connect (read-only) using $env:OVPNBASE_SMOKE_PASS, dump results, close.
if ($SmokeTest) {
    $Window.Add_ContentRendered({
            $ui.PbApiPass.Password = $env:OVPNBASE_SMOKE_PASS
            if ($env:OVPNBASE_SMOKE_USER) { $ui.TbApiUser.Text = $env:OVPNBASE_SMOKE_USER }
            if ($env:OVPNBASE_SMOKE_ROUTER) { $ui.TbRouter.Text = $env:OVPNBASE_SMOKE_ROUTER }
            $ui.BtnConnect.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $script:SmokeTimer = New-Object System.Windows.Threading.DispatcherTimer
            $script:SmokeTimer.Interval = [TimeSpan]::FromSeconds(1)
            $script:SmokeStart = Get-Date
            $script:SmokeTimer.Add_Tick({
                    if ((-not $script:Busy -and $script:State) -or ((Get-Date) - $script:SmokeStart).TotalSeconds -gt 60) {
                        $script:SmokeTimer.Stop()
                        $ui.BtnPreview.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
                        $ui.BtnSetupPreview.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
                        $r = @("STATE=$([bool]$script:State)", "CHECKS=$(@($script:Checks).Count)", "GRID=$(@($ui.DgDiag.ItemsSource).Count)",
                            "SERVERS=$($ui.LbServers.Items.Count) SEL=$(Get-SelectedServerName)", "PORT=$($ui.TbPort.Text) :: $($ui.TbPortCheck.Text)",
                            "CERTS=$(@($ui.DgCerts.ItemsSource).Count) SRVGRID=$(@($ui.DgServers.ItemsSource).Count)", "SUMINFO=$($ui.TbSumInfo.Text) TIP1=$((@($ui.DgDiag.ItemsSource)[3]).Tip -replace "`n",' | ')", "STATUS=$($ui.TbStatus.Text)",
                            "YEAR=$($ui.TbYear.Text) CERT=$($ui.TbCertName.Text) CN=$($ui.TbCertCn.Text) NEWSRV=$($ui.TbNewServer.Text) DAYS=$($ui.TbDays.Text) CUT=$($ui.TbCutDate.Text)",
                            "HOST=$($ui.TbHost.Text) ROUTES=$((Get-RoutesFromUi) -join ',') FRIENDLY=$($ui.TbFriendly.Text)",
                            "PERM-MISSING=$($script:SmokePerm.Missing -join ',')", "PERM-FIX:", ($script:SmokePerm.Fix -join "`r`n"),
                            "USERS=$($ui.LbUsers.Items.Count) USERPROFILE=$($ui.TbUserProfile.Text) MODE=$(Get-AuthMode) LOCALENABLED=$($ui.GrLocal.IsEnabled)",
                            "SETUP-BANNER: $($ui.TbSetupBannerTitle.Text) | toggle=$($ui.BtnSetupToggle.Content) | runVis=$($ui.BdSetupRun.Visibility) | header2=$(if ($ui.TabSetup.Header -is [System.Windows.Controls.StackPanel]) { $ui.TabSetup.Header.Children[$ui.TabSetup.Header.Children.Count-1].Text })",
                            "SETUP-STATUS:", $ui.TbSetupStatus.Text, "CA-STATUS: $($ui.TbCaStatus.Text)", "SETUP-PLAN:", $ui.TbSetupPlan.Text,
                            "PLAN:", $ui.TbPlan.Text, "LOG:", $ui.TbLog.Text)
                        [System.IO.File]::WriteAllText((Join-Path $LogDir 'smoke.txt'), ($r -join "`r`n"), [System.Text.Encoding]::UTF8)
                        $Window.Close()
                    }
                })
            $script:SmokeTimer.Start()
        })
}

Write-OvpnLog "OvpnBase запущено (PowerShell $($PSVersionTable.PSVersion))"
if ($PSVersionTable.PSVersion.Major -lt 7) { Write-OvpnLog -Level WARN 'Windows PowerShell 5.1: перевірка паскею ключа недоступна. Рекомендовано PowerShell 7 (pwsh).' }
[void]$Window.ShowDialog()
