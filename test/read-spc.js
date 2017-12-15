const fs = require('fs')
const path = require('path')
const test = require('ava')
// Cach require module minh da viet
const SPCPayload = require('../src/spc/spc-payload')

const PATH_TO_SPC = path.join(__dirname, '../ksm/data/FPS', 'spc1.bin')

// const spc = new SPCPayload([1,2,3,4])
// spc.getPayload() /* ? */

test.cb('Read buffers from spc1.bin', t => {
  // Read demo spc1.bin file located in `~/.data/FPS/spc1.bin`
  fs.readFile(PATH_TO_SPC, null, (err, data) => {
    if (err) {
      console.error(err)
      return
    }
    // console.log('Read spc success:', data)
    const spcPayload = new SPCPayload(data)
    console.log(spcPayload.getPayload())
    t.is(true, true)
    t.end()
  })
})
