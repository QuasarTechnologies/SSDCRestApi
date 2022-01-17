/// Designed by AnaSoft Inc. 2018-2021
/// https://www.anasoft.net/restapi
/// 
///Instructions:
///
///1.update db connection in Api/appsettings.json (and Test/appsettings.json for full version))
///2.run Api project
///3.run all tests in Test project
///4.add new entity class(es) ("code first") in Entity/Entity 
///5.and run Entity/CodeGeneratorUtility.bat to trigger smart code scaffolding to generate 100s lines of quality code for
///6.domain, service, controller, api and tests. Test your service with generated integration xunit tests(IS4 and JWT), Postman tests(IS4 and JWT) json, Swagger test/documentation(IS4 and JWT) and db migration script
///7.run Api project
///8.run all generated default xunit tests in Test project
///9.run default Postman tests with run-postman-tests.ps1 script which run tests and create 2 (summary and detailed) htlm tests reports which can be emailed.
///
///In case you are doing "database first" - create entity classes from tables definition and set "UseMigrationService": false in Api project
///
///More video instructions:
///https://www.anasoft.net/restapi
///******************************************************************************************



2018-2021(c) Anasoft Inc.
(c)Note that there is no restriction to use, copy, modify, and distribute software created with this Visual Studio extension 
template. THE EXTENSION RESSEL IS FORBIDDEN! Created solution using this template may contain code with unintentional flaws 
or limitations. Please adjust created solution to your needs and test it before any production use. IN NO EVENT SHALL OWNER 
OF THIS EXTENSION BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST 
PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE OWNER HAS BEEN ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.