/* eslint-disable @typescript-eslint/no-non-null-assertion */
import nextConnect from 'next-connect'
import multer from 'multer'
import cors from 'nextjs-cors'
import { NextApiRequest, NextApiResponse, PageConfig } from 'next'
import {
  BlobServiceClient,
  BlockBlobClient,
  ContainerClient,
} from '@azure/storage-blob'
import getStream from 'into-stream'
import internal from 'stream'
import Error from 'next/error'

//** Setting up cors policy */
const allowCors =
  (
    fn: (
      arg0: NextApiRequest & { files: Express.Multer.File[] },
      arg1: NextApiResponse
    ) => unknown
  ) =>
  async (
    req: NextApiRequest & { files: Express.Multer.File[] },
    res: NextApiResponse
  ) => {
    res.setHeader('Access-Control-Allow-Credentials', 'true')
    res.setHeader('Access-Control-Allow-Origin', '*')
    // another common pattern
    // res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,OPTIONS,PATCH,DELETE,POST,PUT'
    )
    res.setHeader(
      'Access-Control-Allow-Headers',
      'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    )
    if (req.method === 'OPTIONS') {
      res.status(200).end()
      return
    }
    return await fn(req, res)
  }

const upload = multer({
  storage: multer.memoryStorage(),
})

export const config: PageConfig = {
  api: {
    bodyParser: false,
  },
}
//** Setting up Azure configurations */
const blobServiceClient: BlobServiceClient =
  BlobServiceClient.fromConnectionString(process.env.AZURE_CONNECTION_STRING!)
const containerClient: ContainerClient = blobServiceClient.getContainerClient(
  process.env.AZURE_CONTAINER_NAME!
)
const getBlobName = (originalName: string): string => {
  const identifier = Math.random().toString().replace(/0\./, '') // remove "0." from start of string
  return `${identifier}-${originalName}`
}
async function uploadFileToBlob(
  blobname: string,
  stream: internal.Readable,
  streamLength: number
): Promise<string> {
  try {
    const blobClient: BlockBlobClient =
      containerClient.getBlockBlobClient(blobname)
    await blobClient.uploadStream(stream, streamLength)
    return 'SUCCESS'
  } catch (err) {
    throw new Error({ statusCode: 503, title: 'Server Error' })
  }
}

const handler = nextConnect<
  NextApiRequest & { files: Express.Multer.File[] },
  NextApiResponse
>({
  onError(error, req, res) {
    res.status(501).json({ error: `There was an error! ${error.message}` })
  },
  onNoMatch(req, res) {
    res.status(405).json({ error: `Method '${req.method}' Not Allowed` })
  },
  attachParams: true,
})
  .use(upload.array('files'))
  .post(async (req, res) => {
    const blobName = getBlobName(req?.files[0]?.originalname),
      stream = getStream(req?.files[0]?.buffer),
      streamLength = req?.files[0]?.buffer.length
    const message = await uploadFileToBlob(blobName, stream, streamLength)
    if (message === 'SUCCESS') {
      const blobUrl = `https://${process.env.AZURE_ACCOUNT_NAME}.blob.core.windows.net/${process.env.AZURE_CONTAINER_NAME}/${blobName}`
      return res.status(200).json({ url: blobUrl })
    }
  })

export default allowCors(handler)
