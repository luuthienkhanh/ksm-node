const fs = require('fs') // Module cua NodeJS dung de doc file

// Ham nay se doc file, khi nao doc xong moi resolve data, nen la bat dong bo
const readFile = (filePath) => {
    console.log(filePath)
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                // Cho nay no bi loi ne, nen khong in text duoc
                console.log(err.message)
                reject(err)
            } else {
                resolve(data)
            }
        })
    })
}

class Demo {
    constructor(param1, param2) {
        this.param1 = param1
        this.param2 = param2
    }

    sum() {
        return this.param1 + this.param2
    }

    concat() {
        // Anh thay cai nut mau xanh la ham nay da duoc test chay an toan
        return `${this.param1} love ${this.param2}`
    }

    isEqual() {
        return this.param1 === this.param2
    }

    async hamBatDongBo(filePath) {
        return await readFile(filePath)
    }
}

module.exports = Demo