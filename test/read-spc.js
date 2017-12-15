const fs = require('fs')
const path = require('path')
const PATH_TO_SPC = path.join(__dirname, '../.data/FPS', 'spc1.bin')

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
  // console.log('Convert to bytes: ', data)
});

