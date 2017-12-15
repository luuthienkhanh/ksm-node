const fs = require('fs')
const path = require('path')
const test = require('ava')

const PATH_TO_SPC = path.join(__dirname, '../ksm/data/FPS', 'spc1.bin')

test.cb('Read buffers from spc1.bin', t => {
  // Read demo spc1.bin file located in `~/.data/FPS/spc1.bin`
  fs.readFile(PATH_TO_SPC, null, (err, data) => {
    if (err) {
      console.error(err)
      return
    }
    console.log('Read spc success:', data)
    const buffer = new Uint8Array(data)
    buffer.forEach((value, index) => {
      console.log(index, value)
    })
    t.is(true, true)
    t.end()
  })
})
