## License

**© Copyright 2021 Visa. All Rights Reserved.**

*NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of
and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property
rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*

*By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (
developer.visa.com/privacy).In addition, all permissible uses of the Software must be in support of Visa products,
programs and services provided through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE
SOFTWARE AND ANY ASSOCIATED INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS”
BASIS WITHOUT WARRANTY OR CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of
their respective owners, used for identification purposes only, and do not imply product endorsement or affiliation with
Visa. Any links to third party sites are for your information only and equally do not constitute a Visa endorsement.
Visa has no insight into and control over third party content and code and disclaims all liability for any such
components, including continued availability and functionality. Benefits depend on implementation details and business
factors and coding steps shown are exemplary only and do not reflect all necessary elements for the described
capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require
development,implementation and resources by you based on your business and operational details. Please refer to the
specific API documentation for details on the requirements, eligibility and geographic availability.*

*This Software includes programs, concepts and details under continuing development by Visa. Any Visa
features,functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s
discretion.The timing of widespread availability of programs and functionality is also subject to a number of factors
outside Visa’s control,including but not limited to deployment of necessary infrastructure by issuers, acquirers,
merchants and mobile device manufacturers.*

**<span style="color:red">This sample code is licensed only for use in a non-production environment for sandbox testing.
See the license for all terms of use.</span>**


##About
This project contains samples which illustrate how to create JWE & JWS in NodeJS.
For this, it uses library node-jose for implementing JOSE standard based JWE / JWS.

##Prerequisites
 - Node ~v13.6.0
 - NPM for Package management

If you don't have Node install, please get it from https://nodejs.org/en/download/

##Running locally
Run the following command to install all the dependencies:

```npm clean install```

After successfully installing the dependencies, run the following command to start the app:

```npm start```

The server should start at port 3000 by default.

Now hitting URL http://localhost:3000/ will redirect to the Swagger Doc (Open API Doc) for the services available.

![Encryption Rest Service](Encryption-Rest-Service.png)