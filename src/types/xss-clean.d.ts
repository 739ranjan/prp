// // declare module 'xss-clean' {
// //   const value: Function;

// //   export default value;
// // }
// import xss from 'xss-clean';

// // Use xss as 'any' type
// const sanitizedInput: any = xss(someInput);
// src/types/xss-clean.d.ts
declare module 'xss-clean' {
  function xss(): any;
  export = xss;
}
