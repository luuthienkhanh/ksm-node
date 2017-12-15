// This file will be use to parse SPC message
class SPCPayload {
  constructor(bytes) {
    this.payload = Buffer.from(bytes)
  }

  getPayload() {
    return this.payload
  }
  
  vidu() {
    return "Hello"
  }
}

// Test real-time with quokka
// const spcPayload = new SPCPayload([1, 2, 3])
// Day la class em copy lai cua project java, cach dung cung giong wallaby
// Khi co loi no se quang ra lien luon
// spcPayload /* ? */
// console.log(spcPayload.getPayload())

// Lenh nay se dung rat nhieu, export module ra ngoai
module.exports = SPCPayload
