# Secure Bootloader and Trusted Application Execution

Target board: STMicroelectronics NUCLEO-WL55JCx  

![The NUCLEO-WL55JCx Board](README_Content/NUCLEO-WL55JCx.jpg)

## 1 Preliminaries: Getting familiar

### 1.1 Introduction
 <div style="text-align: justify">
This work focuses on implementing trusted boot and validation of trusted installed applications on the dual core STM32 NUCLEO-WL55JCx microcontroller.
In this direction we developed a bootloader that is entitled as secure for:
</div>
&nbsp;

1. Being installed in secure flash memory area
2. Guaranteeing to be the initial execution point
3. Verifying the trustworthiness of a user application prior to jumping at it

### 1.2 NUCLEO-WL55JCx

Board features:
* Dual core with M4 and M0+ cores
* 256K flash and 64K SRAM memories
* Security features for CPU M0+ such as secure peripherals, secure flash (RDP, WRP, PCROP, HDP)
* Trust-zone controller
* RF transceiver supporting LoRa modulations

### 1.3 Implementation
 <div style="text-align: justify">
A main functionality of a bootloader is to redirect the CPU execution to a particular address offset in memory where an application binary is installed.
So to start with, this project involves two binaries, that is, the bootloader and the trusted user application.
Both binaries execute on the M0+ core which is the only privileged CPU allowed to access secure memories and peripherals.
The M0+ core, though, can be released only by the M4 core.
As a result one more binary application is involved for the M4 core that should, at least, include the system clock configuration and the M0+ release operation.
Finally, to trust an application it requires the signature of the developer, the address offset of this application in flash and its size that will be used for verification by the secure bootloader.
This batch of information is included in a binary that will be referred to as Trusted Info Structure or <b>TIS</b>.
</div>

### 1.4 Flash partition and applied security
 <div style="text-align: justify">
We are obliged to separate the flash memory in secure and non-secure areas since the M4 core is considered <b>non-secure</b> while the bootloader, the M0+ user application and the TIS must be executed in the <b>secure world</b>.
The way that flash is partitioned and secured can be seen in <b>Fig. 1</b>.
Since the role of the M4 application is to configure the system clocks and release the M0+ core, it requires less than 6K of flash resources.
The flash page size for the current microcontroller is 2K, so, 3 pages are occupied for the M4 application starting from the base address of the flash, that, is <b>0x08000000</b>.
The rest flash starting from offset <b>0x08001800</b> is set as secure area.
A particular subset of the secure area is further set as a hide protection area to accommodate the secure bootloader that is installed in offset <b>0x08020000</b>.
The M0+ user application is installed in offset <b>0x08001800</b> and the TIS in offset <b>0x0801F800</b> which is the last page before the HDP area begins.
</div>
&nbsp;

![Flash partition and applied security](README_Content/Flash_Partition.png)  
*Fig. 1 Flash partition and applied secure areas*

 <div style="text-align: justify">
It is important to note that the M4 application as well as the ST-Link debug interface do not have read, write or execute rights to the secure area.
Moreover, the M0+ core can read, write or execute in the HDP area only after reset and only before closing it.
After that, this area is no longer accessible by any means.
The rest secure area allows any type of access only to the M0+ core or a secure DMA.
To conclude, only the secure bootloader can access the HDP area which makes it considered as a custom ROM that, furthermore, is guaranteed to be the first execution point when the M0+ is released allowing to have root of trust.
</div>

### 1.5 Boot sequence

 <div style="text-align: justify">
This section puts together all the described binaries above and walks through the steps that compose the secure booting of the system <b>(Fig. 3)</b>.
</div>
&nbsp;

1. <div style="text-align: justify">
The starting point is the M4 application with the simple but vital role of setting up the system’s clocks and then releasing the M0+ core for execution.
</div>
2. <div style="text-align: justify">
Based on the option bytes configuration the M0+ starts execution at offset <b>0x08020000</b>, that is, running the secure bootloader in the HDP area.
The final purpose of the secure bootloader is to jump to a trusted application but prior to doing so it has to make verification checks.
If any verification step fails the secure bootloader denies to jump to a user application.
</div>
3. <div style="text-align: justify">
To start with,  the secure bootloader is the only one allowed to make authorized actions on the STSAFE-A110, so, it has to make sure that the secure element can be trusted.
It is important to clarify that the secure element does not play any role in having secure boot but it will be needed by the user application, so, it must be trusted.
The STSAFE-A110 has an immutable record of a so called leaf certificate that uniquely identifies an STSAFE-A110 peripheral and it is signed by STMicroelectronics (STM) during production.
The secure bootloader uses the STM root certificate which enfolds the public key that can be used to verify the STSAFE-A110 leaf certificate as seen in <b>Fig. 2</b>.
If that verification succeeds it is then clear that the secure element is trustworthy.
</div
&nbsp;

![Leaf certificate verification](README_Content/Leaf_Cert_Verification.png)  
*Fig. 2 Leaf certificate verification*


4. <div style="text-align: justify">
The next and final verification is related to the user application.  
This process involves a public certificate of the developer that signed the user application.
This certificate is available to the bootloader and is stored in the STSAFE-A110 secure data partitions.
The reason for storing it in the STSAFE-A110 is that in future an administrative entity may choose to replace it with a fresh certificate for the trusted developer and the secure bootloader HDP secure area should not be allowed to be modified once security is enabled.
In other words, storing the certificate in the HDP area is not recommended.
At this point, the secure bootloader reads the developer’s certificate from STSAFE-A110, parses the public key found in that certificate and extracts the TIS from the flash.
Based on the TIS it calculates the hash of the user application, checks that the signature is generated for this hash and finally according to the developer’s public key it verifies that the signature belongs to the trusted developer.
</div>
5. <div style="text-align: justify">
Upon verifying the user application the bootloader will call the <i><b>CloseExitHDP()</b></i> function to close the hide protection area by setting the HDPADIS bit of the flash access control register 2 and then jump to the user application at offset <b>0x08001800</b>.
</div>
&nbsp;

  ![Boot sequence](README_Content/Boot_Sequence.png)  
*Fig. 3 Boot sequence*

## 2 User Guide: How to Run the Project and Apply Security

### 2.1 Start the STMCubeIDE and Load the Project 

* This project was developed with STM32CubeIDE, so, start your IDE and open the project as follows:  

  ![Open project](README_Content/Open_Project.png)  
&nbsp;


* In the dialog box that appears click on the **Directory** button:  

  ![Import project](README_Content/Import_Project.png)  
&nbsp;

* Navigate in the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader/` root directory and click **Open**:  

  ![Navigate to project](README_Content/Navigate.png)  
&nbsp;

* Then, click **Finish** to load the project. The **Project Explorer** on the left side of the window should look like the picture below:

  ![Project Explorer](README_Content/Project_Explorer.png)
&nbsp;

  > NOTE: In the picture above you can see two nested projects, one for the M4 and another for the M0+ cores.

  > **ATTENTION**: Before we start, make sure that the NUCLEO-WL55JCx board is connected to your PC via USB. 

### 2.2 The Role of the Contents in the `Developer_Trusted_Certificate_Keypair/` directory

* Open a file explorer, locate and move to your project in the following directory:
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Developer_Trusted_Certificate_Keypair`

* You should see the following files:

        Developer_Trusted_Certificate_Keypair/
            |
            |_ generate_keypair_certificate.sh
            |_ developer_certificate_c_array.sh
            |_ sign_binary.sh

* The `generate_keypair_certificate.sh` does the following actions:  
  * Generates public and private ECDSA keypair.  
  * Creates the developer's self signed certificate in *.pem*, *.der* and *.hex* formats based on that keypair.  
  * Creates a C byte array of the developer's certificate and stores it in the `developer_certificate_array.h` file.  
   
  > NOTE:  
  > The byte array found in the `developer_certificate_array.h` file will later be stored in the STSAFE-A110 secure element. 


* The `developer_certificate_c_array.sh` script is called by the `generate_keypair_certificate.sh` to create the C byte array of the certificate.

* The `sign_binary.sh` creates the Trusted Info Structure (TIS) binary that contains the following fields:
  * The STM32 magic number so that the binary is recognized by the STMCubeProgrammer
  * The offset in flash where the trusted user application will be located
  * The size of the trusted user application
  * The signature of the trusted user application based on the developer's private key
  
  > NOTE:  
  > The TIS binary will be used by the Secure Bootloader to validate the trustworthiness of the trusted user application.

### 2.3 Generate an ECDSA Keypair and a Certificate for the Developer

* Open a file explorer, locate and move to your project in the following directory:
 `/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Developer_Trusted_Certificate_Keypair/`

* In a terminal, run the command:
`./generate_keypair_certificate.sh`

* The terminal will prompt you to fill the required information for the certificate.

* Once done, you should now see the following extra files generated in the `Developer_Trusted_Certificate_Keypair/` directory:

        Developer_Trusted_Certificate_Keypair/
            |
            |_ developer_certificate.der
            |_ developer_certificate.hex
            |_ developer_certificate.pem
            |_ developer_certificate_array.h
            |_ developer_private_key.pem
            |_ developer_public_key.pem      
            
The keypair and certificate is now generated and ready to be used!

### 2.4 Prepare the TIS Binary

* Locate you custom application binary that will be considered as the M0+ truster user application and copy it to the following directory:
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Developer_Trusted_Certificate_Keypair/`        

* Rename your custom application binary to have the following name:  
`UserApplication_CM0PLUS.bin`

* In a terminal, run the command below to create the TIS binary:  
`./sign_binary.sh`

  > **ATTENTION**:  
  > It is IMPORTANT to give the custom application binary the correct name as given above, otherwise the *sign_binary.sh* script will fail to create the TIS binary.                                       

### 2.5 Build and Run the M4 Application

* In the **Project Explorer**, right click on the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM4` project and select **Build**:

  ![Build the M4 application](README_Content/Build_M4.png)
&nbsp;

* On the **Toolbar** click on the red-highlighted button as seen in the picture below and select  
__Run As -> 1 STM32 Cortex-M C/C++ Application__:

  ![Run the M4 Application](README_Content/Run_Project.png)
&nbsp;

* In the dialog box that appears click **OK** to download the M4 Application binary to the NUCLEO-WL55JCx flash memory.

  ![Download the M4 Application binary](README_Content/Download_M4_Application.png)
&nbsp;

  > NOTE: The M4 Application binary will be downloaded in offset **0x08000000** of the flash.

### 2.6 Store the Developer's Certificate in the STSAFE-A110 Secure Element

<div style="text-align: justify">
This step requires to flash and run the M0+ Secure Bootloader in <b>OEM Setup</b> mode.
This mode is ONLY needed so that we make the initial configurations for the STSAFE-A110 secure element.
In later steps the Secure Bootloader will be flashed again in <b>Normal</b> mode.
</div>

* In the **Project Explorer** open the following file:
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Core/Src/main.c`

* Locate the line seen in the picture below and set the `OEM_MODE` to **1**. 

  ![Set to OEM Mode](README_Content/OEM_Mode.png)
&nbsp;

* Open the file below and copy its contents to the clipboard:
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Developer_Trusted_Certificate_Keypair/developer_certificate_array.h`

  > REMINDER: The contents of this file is the byte array of the developer's certificate. 

* Open the file below:  
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Core/Inc/stsafe_certs.h`

* In this file locate a record similar to the one in the picture below:

  ![Developer certificate byte array](README_Content/Developer_Certificate_Array.png)
&nbsp;

* Replace this record with the previously copied byte array of the developer's certificate.

  > NOTE:
  > Now, we have set the correct developer's certificate that we need to store in the STSAFE-A110 secure element.

* In the **Project Explorer**, expand the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/` nested project and open the `STM32WL55JCIX_FLASH.ld` linker script file.

* In the linker script file search for the following record and change the flash offset to the desired one:

  ![M0+ core linker script](README_Content/M0_Linker_Script.png)
&nbsp;

  > NOTE: By default the offset is 0x08020000 which leaves 128K to fit the secure bootloader.

* Open the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Common/System/system_stm32wlxx.c` file, uncomment the record in line **128** and set the vector table offset in line **142** as desired: 

  ![M0+ Core vector table offset](README_Content/Vector_Table_Offset.png)
&nbsp;

  > NOTE: In line 142 the offset is **0x00020000** since it will be added to the flash base address which is **0x08000000**.

* In the **Project Explorer**, right click on the **WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS** project and select **Build**:

  ![Build the M0+ Secure Bootloader](README_Content/Build_M0PLUS.png)
&nbsp;

* On the **Toolbar** click on the red-highlighted button as seen in the picture below and select  
__Run As -> 1 STM32 Cortex-M C/C++ Application__:

  ![Run the M4 Application](README_Content/Run_Project.png)
&nbsp;

* In the dialog box that appears click **OK** to download the M0+ Secure Bootloader binary to the NUCLEO-WL55JCx flash memory.

  ![Download the M0+ Secure Bootloader binary](README_Content/Download_M0PLUS_Application.png)
&nbsp;

  > NOTE: The M0+ Secure Bootloader binary will be downloaded in offset **0x08020000** of the flash.
 
* Open the STM32CubeProgrammer and click the **Connect** button at the top right corner to connect to the NUCLEO-WL55JCx board:

  ![Connect to the NUCLEO-WL55JCx board](README_Content/Connect.png)
&nbsp;
  
* In the top left corner click on the **OB** button (Option Bytes) and then expand the **Security Configuration Option Bytes** option.  
  
  ![Set the offset where the M0+ core will start execution](README_Content/OB_Set_SBRV.png)
&nbsp;

* Scroll down until you find the `SBRV` field:

  ![Set the value of the SBRV field](README_Content/SBRV_Field.png)
&nbsp;

* In the `SBRV` field set the offset where the M0+ core must start its execution.

  > **IMPORTANT**:  
  > The **SBRV** value is the offset that increments the flash base address and is 4 bytes aligned.
  To make it more clear, if we need the M0+ core to execute from offset 0x08020000 then the offset is 0x20000.
  Since the SBRV is 4 bytes aligned we should divide the 0x20000 value by 4, so, the SBRV value must be 0x8000.
  
  > **NOTE**:  
  > If the developer of this project decides to move the Secure Bootloader to different offset then he must, also, set the SBRV field accordingly.
  Otherwise, the M0+ core may try to start executing from an offset where no binary is stored.  

* **Finally**, reset the system by pressing the reset button on the board.

<div style="text-align: justify">
At this moment the M4 core will execute the M4 Application to configure the system clocks and then release the M0+ core.
When the M0+ core is released it will execute the Secure Bootloader in OEM Setup mode in order to store the developer's certificate to the STSAFE-A110 secure element. 
</div>

### 2.7 Build and Run the M0+ Secure Bootloader in Normal Mode

* In the **Project Explorer** open the following file:
`/WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS/Core/Src/main.c`

* Locate the line seen in the picture below and set the `OEM_MODE` to **0** to use the Secure Bootloader in Normal mode: 

  ![Set to OEM Mode](README_Content/OEM_Mode.png)
&nbsp;

* In the **Project Explorer**, right click on the **WL55JC1_STSAFEA110_PKA_Secure_Bootloader_CM0PLUS** project and select **Build**:

  ![Build the M0+ Secure Bootloader](README_Content/Build_M0PLUS.png)
&nbsp;

* On the **Toolbar** click on the red-highlighted button as seen in the picture below and select  
__Run As -> 1 STM32 Cortex-M C/C++ Application__:

  ![Run the M4 Application](README_Content/Run_Project.png)
&nbsp;

* In the dialog box that appears click **OK** to download the M0+ Secure Bootloader binary to the NUCLEO-WL55JCx flash memory.

  ![Download the M0+ Secure Bootloader binary](README_Content/Download_M0PLUS_Application.png)
&nbsp;

  > NOTE:  
The offset where the Secure Bootloader will execute is, already, set as 0x08020000 in the previous section.  
As a result, the M0+ Secure Bootloader binary will be downloaded in offset **0x08020000** of the flash.

<div style="text-align: justify">
At this point, both the M4 Application and the M0+ Secure Bootloader are downloaded in the flash ready to execute.
By resetting the board the M4 core will execute, again, the M4 Application to configure the system clocks and then release the M0+ core.
When the M0+ core is released it will execute the Secure Bootloader in Normal mode and will try to find a valid trusted user application to jump to.
It will fail, though, to jump because we haven't downloaded neither the trusted user application nor the required TIS binary yet.
</div>

* Before we further proceed make sure that you have installed the **Minicom** serial terminal.

* Open a terminal and run the following command:  
`minicom -D /dev/ttyACM0 -c on`

* Reset the board again and expect to see the following output:

  ![No application found to jump](README_Content/No_Application.png)
&nbsp;

### 2.8 Flash the M0+ User Application and TIS Binaries

<div style="text-align: justify">
Before proceeding make sure that you have set the correct offset for the vector table in the linker script file and the <b>system_stm32wlxx.c</b> file for your M0+ trusted user application in the same way as in section 2.6.
In this project we set the offset to <b>0x08001800</b> which corresponds to the page after the M4 Application flash area.
</div>

* Open the STM32CubeProgrammer and click the **Connect** button at the top right corner to connect to the NUCLEO-WL55JCx board:

  ![Connect to the NUCLEO-WL55JCx board](README_Content/Connect.png)
&nbsp;

* In STMCubeProgrammer click on the second button (red-highlighted area) and do the following:
  * Click **Browse** and choose the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader/CM0PLUS/Developer_Trusted_Certificate_Keypair/UserApplication_CM0PLUS.bin` binary (green-highlighted area).
  * Set the address offset in flash to download it as **0x08001800** (blue-highlighted area).
  * Click the **Start Programming** button to download the binary to flash (purple-highlighted area).  

    ![Flash the M0+ Trusted User Application binary](README_Content/Download_M0_User_Application.png)
&nbsp;

* In the same manner download the TIS binary:
  * Click **Browse** and choose the `WL55JC1_STSAFEA110_PKA_Secure_Bootloader/CM0PLUS/Developer_Trusted_Certificate_Keypair/trusted_application_struct.bin` binary (green-highlighted area).
  * Set the address offset in flash to download it as **0x0801F800** (blue-highlighted area).
  * Click the **Start Programming** button to download the binary to flash (purple-highlighted area).  

    ![Flash the TIS binary](README_Content/Download_TIS.png)
&nbsp;

  > **NOTE**:  
  The Secure Bootloader is set by default to read the TIS binary from offset **0x0801F800**. This offset is the last page before the Secure Bootloader area.

* Open again a terminal and run the following command:  
`minicom -D /dev/ttyACM0 -c on`

* Reset the board again and expect to see the following output:

  ![Valid application found to jump](README_Content/Valid_Application.png)
&nbsp;

* If the M0+ User Application or the TIS binary are not correctly flashed or if the TIS is not generated correctly for this application you should see the following output:

  ![Invalid application found, fail to jump](README_Content/Invalid_Application.png)
&nbsp;

### 2.9 Enable Security (Option Bytes)

<div style="text-align: justify">
At this point, we are ready to apply security for the flash memory. The secured flash area will start from offset <b>0x08001800</b> until the end of the flash.
Additionally, part of the secure area will be further set as hide protection area (HDP) for the Secure Bootloader.
The HDP area will start from offset <b>0x08020000</b> until the end of the flash.
</div>

* Open the STM32CubeProgrammer and click the **Connect** button at the top right corner to connect to the NUCLEO-WL55JCx board:

  ![Connect to the NUCLEO-WL55JCx board](README_Content/Connect.png)
&nbsp;
  
* In the top left corner click on the **OB** button (Option Bytes) and then expand the **Security Configuration Option Bytes** option.  
  
  ![Set the offset where the M0+ core will start execution](README_Content/OB_Set_SBRV.png)
&nbsp;

* Make the following configurations and then click the **Apply** button:
  * Set the `SFSA` to **0x3** (Page 3 or offset 0x08001800)
  * Uncheck the `FSD`
  * Set the `HDPSA` to **0x40** (Page 128 or offset 0x08020000)
  * Uncheck the `HDPAD`
  
* The configurations should look as in the picture below:

  ![Set the flash security through the Option Bytes](README_Content/Set_Security_OB.png)
&nbsp;

* Expand the **Security Configuration Option Bytes** option and make sure that the ESE is checked indicating that flash security is enabled:

  ![Validate that the security is enabled](README_Content/Validate_Security_Enabled.png)
&nbsp;

<div style="text-align: justify">
At this point, all the binaries are correctly installed and the flash memory is secured.
From now on, only the M0+ core can access the secure area which is no longer accessible neither by the M4 core or the debug interface.
Additionally, the HDP area can ONLY be accessed by M0+ core and ONLY after a reset. Once the HDP area is closed it is no longer accessible not even by the M0+ core. 
</div>

### 2.10 Release the security

The security can be released by regression of the read out protection level (RDP). Follow the next steps to undo any set security:

* Expand the **Read Out Protection** option, set the **RDP** to **BB** and click the **Apply** button:

  ![Set RDP to BB](README_Content/Set_RDP_BB.png)
&nbsp;

* Now, in the **Read Out Protection** option set the **RDP** to **AA**, in the **Security Configuration Option Bytes ESE** option uncheck the **ESE** and finally click the **Apply** button:

  ![Set RDP to AA and uncheck ESE](README_Content/Set_RDP_AA.png)
&nbsp;

At this point the security is deactivated!

* Expand the **Security Configuration Option Bytes** option and expect to see the values as in the picture below which means that security is deactivated:

  ![Validate that security is deactivated](README_Content/Security_Deactivated.png)
&nbsp;

Based on the picture above:

* The **SFSA** field is set to **0x7f** which indicates that no secure area is set.
* The **FSD** field is checked which indicates that security is disabled.

> **NOTE**:  
In the picture above, the **HDPSA** field is still set with the previous HDP area and the **HDPAD** is unchecked which means that the HDP area is enabled.
These values, though, do not have any effect at the moment because security is disabled.  
> If you wish, you can set the **HDPSA** to **0x7f**, check the **HDPAD** and then click the **Apply** button to reset them to the default values.   


> **ATTENTION**:  
> Be careful not to set the RDP level to **CC** for it will lock any configurations made in the option bytes permanently.
> In such case, any security set cannot be undone.   

## 3 References
1. _STMicroelectronics, RM0453 Rev 2_  
_STM32WL5x advanced Arm®-based 32-bit MCUs with sub-GHz radio solution_ 


## 4 About

Developer: Dimitrios Bakoyiannis  
E-mail: d.bakoyiannis@gmail.com, dbakoyiannis@hmu.gr