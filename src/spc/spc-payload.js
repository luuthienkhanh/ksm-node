// This file will be use to parse SPC message
class SPCPayload {
  constructor(bytes) {
    this.payload = Buffer.from(bytes)
  }

  getPayload() {
    return this.payload
  }
}

// Test real-time with quokka
const spcParser = new SPCPayload([1, 2, 3])
console.log(spcParser.getPayload())

module.exports = SPCPayload
