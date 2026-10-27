/** Compile-time declaration for the already reviewed same-user .mjs runner.
 * No second implementation, runtime API or published artifact.
 */
export interface LinuxOneShotBinding {
  operationId:string;
  deviceId:string;
  currentVersion:string;
  targetVersion:string;
  targetRoot:string;
}
export interface LinuxOneShotOptions {
  home?:string;
  operationId:string;
  deviceId:string;
  currentVersion:string;
  targetVersion:string;
  assertAdmission:(binding:LinuxOneShotBinding)=>Promise<boolean>;
  verifyPinnedTarget:(binding:LinuxOneShotBinding)=>Promise<boolean>;
  invoke?:(exe:string,args:string[])=>
    {status:number|null;error?:Error;signal?:string|null};
}
export function launchDetachedLinuxUpgrade(
  options:LinuxOneShotOptions,
):Promise<Readonly<{status:"launched";operationId:string;unit:string}>>;
