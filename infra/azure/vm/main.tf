# Create a resource group to hold everything
resource "azurerm_resource_group" "azure-rg" {
  name     = "linux-vm-rg"
  location = "eastus"
}

# Create a minimal virtual network for the VM
resource "azurerm_virtual_network" "vnet" {
  name                = "vm-vnet"
  address_space       = ["10.0.0.0/28"]
  location            = azurerm_resource_group.azure-rg.location
  resource_group_name = azurerm_resource_group.azure-rg.name
}

# Create a single subnet within the virtual network
resource "azurerm_subnet" "subnet" {
  name                 = "vm-subnet"
  resource_group_name  = azurerm_resource_group.azure-rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.0.0/28"]
}

# Create a static public IP for SSH access
resource "azurerm_public_ip" "public_ip" {
  name                = "linux-vm-public-ip"
  location            = azurerm_resource_group.azure-rg.location
  resource_group_name = azurerm_resource_group.azure-rg.name
  allocation_method   = "Static"
  sku                 = "Basic"
}

# Create a security group that allows SSH (port 22)
resource "azurerm_network_security_group" "nsg" {
  name                = "vm-nsg"
  location            = azurerm_resource_group.azure-rg.location
  resource_group_name = azurerm_resource_group.azure-rg.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "<IP space>"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Create a NIC and associate it with the public IP and NSG
resource "azurerm_network_interface" "nic" {
  name                = "linux-vm-nic"
  location            = azurerm_resource_group.azure-rg.location
  resource_group_name = azurerm_resource_group.azure-rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.public_ip.id
  }
}

resource "azurerm_network_interface_security_group_association" "nic_nsg_assoc" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Deploy the Linux Virtual Machine
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "linux-vm"
  location              = azurerm_resource_group.azure-rg.location
  resource_group_name   = azurerm_resource_group.azure-rg.name
  size                  = "Standard_B2s"  # May need to change instance size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.nic.id]
  
  # Use the provided SSH public key
  admin_ssh_key {
    username   = var.admin_username
    public_key = file("~/.ssh/id_ed25519.pub") 
  }

  # Define the OS disk
  os_disk {
    name                 = "linux-os-disk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  # Use the latest Ubuntu 22.04 LTS image
  source_image_reference {
  publisher = "Canonical"
  offer     = "0001-com-ubuntu-server-jammy"
  sku       = "22_04-lts"  
  version   = "latest"
  }
  
}